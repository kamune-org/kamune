package storage

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/pkg/attest"
)

func newTestStorage(t *testing.T) (*Storage, func()) {
	t.Helper()
	f, err := os.CreateTemp("", "kamune-storage-test-*.db")
	require.NoError(t, err)
	require.NoError(t, f.Close())

	storage, err := OpenStorage(
		WithDBPath(f.Name()),
		WithNoPassphrase(),
		WithExpiryDuration(24*time.Hour),
	)
	require.NoError(t, err)

	cleanup := func() {
		assert.NoError(t, storage.Close())
		assert.NoError(t, os.Remove(f.Name()))
	}
	return storage, cleanup
}

// ---------------------------------------------------------------------------
// Peer tests
// ---------------------------------------------------------------------------

func TestStorePeerSetsTimestamps(t *testing.T) {
	a := assert.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	att, err := attest.New()
	a.NoError(err)

	peer := &Peer{
		Name:      "alice",
		PublicKey: att.MarshalPublicKey(),
		// FirstSeen and LastSeen left zero — StorePeer should fill them in.
	}
	a.NoError(storage.StorePeer(peer))

	found, err := storage.FindPeer(att.MarshalPublicKey())
	a.NoError(err)
	a.Equal("alice", found.Name)
	a.False(found.FirstSeen.IsZero(), "FirstSeen should be set automatically")
	a.False(found.LastSeen.IsZero(), "LastSeen should be set automatically")
}

func TestStorePeerRejectsWrongFormat(t *testing.T) {
	a := assert.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	// Raw 32-byte ed25519 key — not allowed, must be PKIX.
	raw32 := make([]byte, 32)
	err := storage.StorePeer(&Peer{Name: "x", PublicKey: raw32})
	a.ErrorIs(err, ErrInvalidPublicKey)

	// 16 bytes — wrong length.
	err = storage.StorePeer(&Peer{Name: "x", PublicKey: make([]byte, 16)})
	a.ErrorIs(err, ErrInvalidPublicKey)

	// 64 bytes — wrong length.
	err = storage.StorePeer(&Peer{Name: "x", PublicKey: make([]byte, 64)})
	a.ErrorIs(err, ErrInvalidPublicKey)

	// Empty.
	err = storage.StorePeer(&Peer{Name: "x", PublicKey: nil})
	a.ErrorIs(err, ErrInvalidPublicKey)

	// Accepts correct format.
	correct := make([]byte, 44)
	err = storage.StorePeer(&Peer{Name: "x", PublicKey: correct})
	a.NoError(err)
}

func TestStorePeerPreservesExplicitTimestamps(t *testing.T) {
	a := assert.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	att, err := attest.New()
	a.NoError(err)

	explicit := time.Now().Add(-1 * time.Hour) // within the 24h expiry window
	peer := &Peer{
		Name:      "bob",
		PublicKey: att.MarshalPublicKey(),
		FirstSeen: explicit,
		LastSeen:  explicit,
	}
	a.NoError(storage.StorePeer(peer))

	found, err := storage.FindPeer(att.MarshalPublicKey())
	a.NoError(err)
	a.True(found.FirstSeen.Equal(explicit))
	a.True(found.LastSeen.Equal(explicit))
}

func TestUpdatePeerLastSeen(t *testing.T) {
	a := assert.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	att, err := attest.New()
	a.NoError(err)

	firstSeen := time.Now().Add(-1 * time.Hour) // within the 24h expiry window
	peer := &Peer{
		Name:      "carol",
		PublicKey: att.MarshalPublicKey(),
		FirstSeen: firstSeen,
		LastSeen:  firstSeen,
	}
	a.NoError(storage.StorePeer(peer))

	newLastSeen := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	a.NoError(storage.UpdatePeerLastSeen(att.MarshalPublicKey(), newLastSeen))

	found, err := storage.FindPeer(att.MarshalPublicKey())
	a.NoError(err)
	a.True(found.FirstSeen.Equal(firstSeen), "FirstSeen must not change")
	a.True(found.LastSeen.Equal(newLastSeen), "LastSeen must be updated")
}

func TestUpdatePeerLastSeenZeroUsesNow(t *testing.T) {
	a := assert.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	att, err := attest.New()
	a.NoError(err)

	peer := &Peer{
		Name:      "dave",
		PublicKey: att.MarshalPublicKey(),
		FirstSeen: time.Now(),
		LastSeen:  time.Now().Add(-1 * time.Hour),
	}
	a.NoError(storage.StorePeer(peer))

	before := time.Now()
	a.NoError(storage.UpdatePeerLastSeen(att.MarshalPublicKey(), time.Time{}))
	after := time.Now()

	found, err := storage.FindPeer(att.MarshalPublicKey())
	a.NoError(err)
	a.False(found.LastSeen.Before(before))
	a.False(found.LastSeen.After(after))
}

func TestUpdatePeerLastSeenMissingPeer(t *testing.T) {
	a := assert.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	// Updating a non-existent peer should be a silent no-op.
	err := storage.UpdatePeerLastSeen([]byte("nonexistent"), time.Now())
	a.NoError(err)
}

func TestListPeers(t *testing.T) {
	a := assert.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	att1, err := attest.New()
	a.NoError(err)
	att2, err := attest.New()
	a.NoError(err)

	a.NoError(storage.StorePeer(&Peer{
		Name:      "peer-1",
		PublicKey: att1.MarshalPublicKey(),
		FirstSeen: time.Now(),
	}))
	a.NoError(storage.StorePeer(&Peer{
		Name:      "peer-2",
		PublicKey: att2.MarshalPublicKey(),
		FirstSeen: time.Now(),
	}))

	peers, err := storage.ListPeers()
	a.NoError(err)
	a.Len(peers, 2)

	names := map[string]bool{}
	for _, p := range peers {
		names[p.Name] = true
	}
	a.True(names["peer-1"])
	a.True(names["peer-2"])
}

func TestListPeersSkipsExpired(t *testing.T) {
	a := assert.New(t)

	f, err := os.CreateTemp("", "kamune-storage-expiry-*.db")
	a.NoError(err)
	a.NoError(f.Close())
	defer func() { _ = os.Remove(f.Name()) }()

	storage, err := OpenStorage(
		WithDBPath(f.Name()),
		WithNoPassphrase(),
		WithExpiryDuration(1*time.Hour),
	)
	a.NoError(err)
	defer func() { _ = storage.Close() }()

	att1, err := attest.New()
	a.NoError(err)
	att2, err := attest.New()
	a.NoError(err)

	// Peer 1 first seen long ago — should be expired.
	a.NoError(storage.StorePeer(&Peer{
		Name:      "old-peer",
		PublicKey: att1.MarshalPublicKey(),
		FirstSeen: time.Now().Add(-48 * time.Hour),
	}))
	// Peer 2 first seen recently — should survive.
	a.NoError(storage.StorePeer(&Peer{
		Name:      "recent-peer",
		PublicKey: att2.MarshalPublicKey(),
		FirstSeen: time.Now(),
	}))

	peers, err := storage.ListPeers()
	a.NoError(err)
	a.Len(peers, 1)
	a.Equal("recent-peer", peers[0].Name)
}

func TestListPeersEmpty(t *testing.T) {
	a := assert.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	peers, err := storage.ListPeers()
	a.NoError(err)
	a.Empty(peers)
}

func TestDeletePeer(t *testing.T) {
	a := assert.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	att, err := attest.New()
	a.NoError(err)

	a.NoError(storage.StorePeer(&Peer{
		Name:      "to-delete",
		PublicKey: att.MarshalPublicKey(),
		FirstSeen: time.Now(),
	}))

	// Verify it exists.
	found, err := storage.FindPeer(att.MarshalPublicKey())
	a.NoError(err)
	a.Equal("to-delete", found.Name)

	// Delete it.
	a.NoError(storage.DeletePeer(att.MarshalPublicKey()))

	// Now FindPeer should fail.
	_, err = storage.FindPeer(att.MarshalPublicKey())
	a.Error(err)
}
