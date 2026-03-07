package kamune

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
		StorageWithDBPath(f.Name()),
		StorageWithAlgorithm(attest.Ed25519Algorithm),
		StorageWithNoPassphrase(),
		StorageWithExpiryDuration(24*time.Hour),
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

	att, err := attest.NewAttester(attest.Ed25519Algorithm)
	a.NoError(err)

	peer := &Peer{
		Name:      "alice",
		PublicKey: att.PublicKey(),
		Algorithm: attest.Ed25519Algorithm,
		// FirstSeen and LastSeen left zero — StorePeer should fill them in.
	}
	a.NoError(storage.StorePeer(peer))

	found, err := storage.FindPeer(att.PublicKey().Marshal())
	a.NoError(err)
	a.Equal("alice", found.Name)
	a.False(found.FirstSeen.IsZero(), "FirstSeen should be set automatically")
	a.False(found.LastSeen.IsZero(), "LastSeen should be set automatically")
}

func TestStorePeerPreservesExplicitTimestamps(t *testing.T) {
	a := assert.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	att, err := attest.NewAttester(attest.Ed25519Algorithm)
	a.NoError(err)

	explicit := time.Now().Add(-1 * time.Hour) // within the 24h expiry window
	peer := &Peer{
		Name:      "bob",
		PublicKey: att.PublicKey(),
		Algorithm: attest.Ed25519Algorithm,
		FirstSeen: explicit,
		LastSeen:  explicit,
	}
	a.NoError(storage.StorePeer(peer))

	found, err := storage.FindPeer(att.PublicKey().Marshal())
	a.NoError(err)
	a.True(found.FirstSeen.Equal(explicit))
	a.True(found.LastSeen.Equal(explicit))
}

func TestUpdatePeerLastSeen(t *testing.T) {
	a := assert.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	att, err := attest.NewAttester(attest.Ed25519Algorithm)
	a.NoError(err)

	firstSeen := time.Now().Add(-1 * time.Hour) // within the 24h expiry window
	peer := &Peer{
		Name:      "carol",
		PublicKey: att.PublicKey(),
		Algorithm: attest.Ed25519Algorithm,
		FirstSeen: firstSeen,
		LastSeen:  firstSeen,
	}
	a.NoError(storage.StorePeer(peer))

	newLastSeen := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	a.NoError(storage.UpdatePeerLastSeen(att.PublicKey().Marshal(), newLastSeen))

	found, err := storage.FindPeer(att.PublicKey().Marshal())
	a.NoError(err)
	a.True(found.FirstSeen.Equal(firstSeen), "FirstSeen must not change")
	a.True(found.LastSeen.Equal(newLastSeen), "LastSeen must be updated")
}

func TestUpdatePeerLastSeenZeroUsesNow(t *testing.T) {
	a := assert.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	att, err := attest.NewAttester(attest.Ed25519Algorithm)
	a.NoError(err)

	peer := &Peer{
		Name:      "dave",
		PublicKey: att.PublicKey(),
		Algorithm: attest.Ed25519Algorithm,
		FirstSeen: time.Now(),
		LastSeen:  time.Now().Add(-1 * time.Hour),
	}
	a.NoError(storage.StorePeer(peer))

	before := time.Now()
	a.NoError(storage.UpdatePeerLastSeen(att.PublicKey().Marshal(), time.Time{}))
	after := time.Now()

	found, err := storage.FindPeer(att.PublicKey().Marshal())
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

	att1, err := attest.NewAttester(attest.Ed25519Algorithm)
	a.NoError(err)
	att2, err := attest.NewAttester(attest.Ed25519Algorithm)
	a.NoError(err)

	a.NoError(storage.StorePeer(&Peer{
		Name:      "peer-1",
		PublicKey: att1.PublicKey(),
		Algorithm: attest.Ed25519Algorithm,
		FirstSeen: time.Now(),
	}))
	a.NoError(storage.StorePeer(&Peer{
		Name:      "peer-2",
		PublicKey: att2.PublicKey(),
		Algorithm: attest.Ed25519Algorithm,
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
		StorageWithDBPath(f.Name()),
		StorageWithAlgorithm(attest.Ed25519Algorithm),
		StorageWithNoPassphrase(),
		StorageWithExpiryDuration(1*time.Hour),
	)
	a.NoError(err)
	defer func() { _ = storage.Close() }()

	att1, err := attest.NewAttester(attest.Ed25519Algorithm)
	a.NoError(err)
	att2, err := attest.NewAttester(attest.Ed25519Algorithm)
	a.NoError(err)

	// Peer 1 first seen long ago — should be expired.
	a.NoError(storage.StorePeer(&Peer{
		Name:      "old-peer",
		PublicKey: att1.PublicKey(),
		Algorithm: attest.Ed25519Algorithm,
		FirstSeen: time.Now().Add(-48 * time.Hour),
	}))
	// Peer 2 first seen recently — should survive.
	a.NoError(storage.StorePeer(&Peer{
		Name:      "recent-peer",
		PublicKey: att2.PublicKey(),
		Algorithm: attest.Ed25519Algorithm,
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

	att, err := attest.NewAttester(attest.Ed25519Algorithm)
	a.NoError(err)

	a.NoError(storage.StorePeer(&Peer{
		Name:      "to-delete",
		PublicKey: att.PublicKey(),
		Algorithm: attest.Ed25519Algorithm,
		FirstSeen: time.Now(),
	}))

	// Verify it exists.
	found, err := storage.FindPeer(att.PublicKey().Marshal())
	a.NoError(err)
	a.Equal("to-delete", found.Name)

	// Delete it.
	a.NoError(storage.DeletePeer(att.PublicKey().Marshal()))

	// Now FindPeer should fail.
	_, err = storage.FindPeer(att.PublicKey().Marshal())
	a.Error(err)
}
