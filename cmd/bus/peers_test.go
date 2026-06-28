package main

import (
	"context"
	"encoding/base64"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
)

func newTestAppWithStorage(t *testing.T) (*App, func()) {
	t.Helper()
	f, err := os.CreateTemp("", "kamune-bus-peers-test-*.db")
	require.NoError(t, err)
	require.NoError(t, f.Close())

	store, err := storage.OpenStorage(
		storage.WithDBPath(f.Name()),
		storage.WithNoPassphrase(),
		storage.WithExpiryDuration(24*time.Hour),
	)
	require.NoError(t, err)

	a := &App{
		ctx:           context.Background(),
		mu:            sync.RWMutex{},
		peers:         make([]PeerInfo, 0),
		dbPath:        f.Name(),
		storeMu:       sync.Mutex{},
		storageReady:  true,
		verifRequests: make(map[int64]*pendingVerification),
	}
	a.storeMu.Lock()
	a.db = store
	a.storeMu.Unlock()

	cleanup := func() {
		_ = store.Close()
		_ = os.Remove(f.Name())
	}
	return a, cleanup
}

func newTestPubKey(t *testing.T) []byte {
	t.Helper()
	att, err := attest.New()
	require.NoError(t, err)
	return att.MarshalPublicKey()
}

func TestAddPeer_Success(t *testing.T) {
	a, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	pub := newTestPubKey(t)
	b64Key := fingerprint.Base64(pub)

	err := a.AddPeer(b64Key, "alice")
	require.NoError(t, err)

	list := a.ListKnownPeers()
	require.Len(t, list, 1)
	assert.Equal(t, "alice", list[0].Name)
	assert.Equal(t, b64Key, list[0].PublicKeyBase64)
	decoded, err := base64.RawURLEncoding.DecodeString(list[0].PublicKeyBase64)
	require.NoError(t, err)
	assert.Equal(t, pub, decoded, "base64 should round-trip to the same bytes")
	assert.False(t, list[0].FirstSeen.IsZero())
	assert.False(t, list[0].LastSeen.IsZero())
	assert.NotEmpty(t, list[0].FingerprintEmoji)
}

func TestAddPeer_DefaultsNameFromFingerprint(t *testing.T) {
	a, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	pub := newTestPubKey(t)
	b64Key := fingerprint.Base64(pub)

	err := a.AddPeer(b64Key, "")
	require.NoError(t, err)

	list := a.ListKnownPeers()
	require.Len(t, list, 1)
	assert.NotEmpty(t, list[0].Name, "name should default to fingerprint pseudonym")
}

func TestAddPeer_InvalidBase64(t *testing.T) {
	a, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	err := a.AddPeer("not-base64-!!!", "alice")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decode base64")
}

func TestAddPeer_WrongLength(t *testing.T) {
	a, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	// Too short — 16 bytes instead of 44.
	short := fingerprint.Base64(make([]byte, 16))
	err := a.AddPeer(short, "alice")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "44 bytes")

	// Too long — 64 bytes.
	long := fingerprint.Base64(make([]byte, 64))
	err = a.AddPeer(long, "alice")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "44 bytes")
}

func TestAddPeer_Empty(t *testing.T) {
	a, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	err := a.AddPeer("", "alice")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

func TestAddPeer_DuplicateRejected(t *testing.T) {
	a, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	pub := newTestPubKey(t)
	b64Key := fingerprint.Base64(pub)

	require.NoError(t, a.AddPeer(b64Key, "alice"))
	err := a.AddPeer(b64Key, "alice2")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestListKnownPeers_SortedByLastSeen(t *testing.T) {
	a, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	// Add three peers with descending LastSeen.
	keys := make([][]byte, 3)
	b64s := make([]string, 3)
	names := []string{"first", "second", "third"}
	for i := range keys {
		keys[i] = newTestPubKey(t)
		b64s[i] = fingerprint.Base64(keys[i])
	}

	// Insert in this order; "third" is most recent.
	require.NoError(t, a.AddPeer(b64s[0], names[0]))
	time.Sleep(20 * time.Millisecond)
	require.NoError(t, a.AddPeer(b64s[1], names[1]))
	time.Sleep(20 * time.Millisecond)
	require.NoError(t, a.AddPeer(b64s[2], names[2]))

	list := a.ListKnownPeers()
	require.Len(t, list, 3)
	assert.Equal(t, "third", list[0].Name, "most recent first")
	assert.Equal(t, "second", list[1].Name)
	assert.Equal(t, "first", list[2].Name, "oldest last")
}

func TestGetPeer_Success(t *testing.T) {
	a, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	pub := newTestPubKey(t)
	b64Key := fingerprint.Base64(pub)
	require.NoError(t, a.AddPeer(b64Key, "alice"))

	got, err := a.GetPeer(b64Key)
	require.NoError(t, err)
	assert.Equal(t, "alice", got.Name)
	assert.Equal(t, b64Key, got.PublicKeyBase64)
}

func TestGetPeer_NotFound(t *testing.T) {
	a, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	pub := newTestPubKey(t)
	b64Key := fingerprint.Base64(pub)

	_, err := a.GetPeer(b64Key)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestGetPeer_InvalidBase64(t *testing.T) {
	a, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	_, err := a.GetPeer("zz!!!")
	assert.Error(t, err)
}

func TestDeletePeer_Success(t *testing.T) {
	a, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	pub := newTestPubKey(t)
	b64Key := fingerprint.Base64(pub)
	require.NoError(t, a.AddPeer(b64Key, "alice"))
	require.Len(t, a.ListKnownPeers(), 1)

	err := a.DeletePeer(b64Key)
	require.NoError(t, err)
	assert.Empty(t, a.ListKnownPeers(), "peer should be gone after delete")
}

func TestDeletePeer_NotFound(t *testing.T) {
	a, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	pub := newTestPubKey(t)
	b64Key := fingerprint.Base64(pub)

	// The underlying storage layer is a no-op when the peer does not
	// exist. The bus's DeletePeer mirrors that — deleting an
	// unknown peer succeeds (it just doesn't change anything) and
	// the cache refresh is still triggered.
	err := a.DeletePeer(b64Key)
	assert.NoError(t, err)
	assert.Empty(t, a.ListKnownPeers())
}

func TestDeletePeer_InvalidBase64(t *testing.T) {
	a, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	err := a.DeletePeer("not-base64-!!!")
	assert.Error(t, err)
}

func TestRenamePeer_Success(t *testing.T) {
	a, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	pub := newTestPubKey(t)
	b64Key := fingerprint.Base64(pub)
	require.NoError(t, a.AddPeer(b64Key, "alice"))

	before, err := a.GetPeer(b64Key)
	require.NoError(t, err)
	originalFirstSeen := before.FirstSeen
	originalLastSeen := before.LastSeen

	require.NoError(t, a.RenamePeer(b64Key, "alice-renamed"))

	after, err := a.GetPeer(b64Key)
	require.NoError(t, err)
	assert.Equal(t, "alice-renamed", after.Name)
	assert.Equal(t, b64Key, after.PublicKeyBase64)
	assert.True(t, after.FirstSeen.Equal(originalFirstSeen),
		"FirstSeen should be preserved across rename")
	assert.True(t, after.LastSeen.Equal(originalLastSeen),
		"LastSeen should be preserved across rename")
}

func TestRenamePeer_TrimsWhitespace(t *testing.T) {
	a, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	pub := newTestPubKey(t)
	b64Key := fingerprint.Base64(pub)
	require.NoError(t, a.AddPeer(b64Key, "alice"))

	require.NoError(t, a.RenamePeer(b64Key, "  bob  "))

	got, err := a.GetPeer(b64Key)
	require.NoError(t, err)
	assert.Equal(t, "bob", got.Name)
}

func TestRenamePeer_EmptyRejected(t *testing.T) {
	a, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	pub := newTestPubKey(t)
	b64Key := fingerprint.Base64(pub)
	require.NoError(t, a.AddPeer(b64Key, "alice"))

	err := a.RenamePeer(b64Key, "")
	assert.Error(t, err)

	err = a.RenamePeer(b64Key, "   ")
	assert.Error(t, err)
}

func TestRenamePeer_NotFound(t *testing.T) {
	a, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	pub := newTestPubKey(t)
	b64Key := fingerprint.Base64(pub)

	err := a.RenamePeer(b64Key, "newname")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestRenamePeer_InvalidBase64(t *testing.T) {
	a, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	err := a.RenamePeer("not-base64-!!!", "newname")
	assert.Error(t, err)
}

func TestRefreshPeersCache_PicksUpStorePeer(t *testing.T) {
	a, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	// Direct write to the storage layer (simulating a peer arriving
	// through the verifier path, not through AddPeer).
	store := a.store()
	require.NotNil(t, store)
	pub := newTestPubKey(t)
	peer := &storage.Peer{
		Name:      "via-storage",
		PublicKey: pub,
	}
	require.NoError(t, store.StorePeer(peer))

	// Cache should not see the new peer until refresh.
	assert.Empty(t, a.ListKnownPeers())

	a.refreshPeersCache()

	list := a.ListKnownPeers()
	require.Len(t, list, 1)
	assert.Equal(t, "via-storage", list[0].Name)
}

func TestRefreshPeersCache_EmptyDB(t *testing.T) {
	a, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	a.refreshPeersCache()
	assert.Empty(t, a.ListKnownPeers())
}

func TestListKnownPeers_DefensiveCopy(t *testing.T) {
	a, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	pub := newTestPubKey(t)
	b64Key := fingerprint.Base64(pub)
	require.NoError(t, a.AddPeer(b64Key, "alice"))

	list := a.ListKnownPeers()
	require.Len(t, list, 1)

	// Mutate the returned slice; the cache should be unaffected.
	list[0].Name = "tampered"
	again := a.ListKnownPeers()
	assert.Equal(t, "alice", again[0].Name, "cache should be unaffected by external mutation")
}

func TestAddPeer_TrimsWhitespace(t *testing.T) {
	a, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	pub := newTestPubKey(t)
	b64Key := fingerprint.Base64(pub)

	err := a.AddPeer("  "+b64Key+"  \n", "alice")
	require.NoError(t, err)
	list := a.ListKnownPeers()
	require.Len(t, list, 1)
	assert.Equal(t, b64Key, list[0].PublicKeyBase64)
}

func TestAddPeer_AcceptsPaddedBase64(t *testing.T) {
	// Raw URL-safe base64 (the canonical form) has no padding.
	// Go's base64 decoder tolerates either form. Verify the bus
	// accepts both.
	a, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	pub := newTestPubKey(t)
	noPad := fingerprint.Base64(pub)
	padded := fingerprint.Base64(pub) + "=="

	require.NoError(t, a.AddPeer(padded, "alice"))
	list := a.ListKnownPeers()
	require.Len(t, list, 1)
	assert.Equal(t, noPad, list[0].PublicKeyBase64,
		"stored base64 should be the canonical un-padded form")
}
