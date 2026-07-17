package main

import (
	"context"
	"encoding/base64"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
)

func newTestAppWithStorage(t *testing.T) (*App, func()) {
	t.Helper()
	a := require.New(t)
	f, err := os.CreateTemp("", "kamune-bus-peers-test-*.db")
	a.NoError(err)
	a.NoError(f.Close())

	store, err := storage.OpenStorage(
		storage.WithDBPath(f.Name()),
		storage.WithNoPassphrase(),
		storage.WithExpiryDuration(24*time.Hour),
	)
	a.NoError(err)

	app := &App{
		ctx:           context.Background(),
		mu:            sync.RWMutex{},
		peers:         make([]PeerInfo, 0),
		dbPath:        f.Name(),
		storeMu:       sync.Mutex{},
		storageReady:  true,
		verifRequests: make(map[int64]*pendingVerification),
	}
	app.storeMu.Lock()
	app.db = store
	app.storeMu.Unlock()

	cleanup := func() {
		_ = store.Close()
		_ = os.Remove(f.Name())
	}
	return app, cleanup
}

func newTestPubKey(t *testing.T) []byte {
	t.Helper()
	a := require.New(t)
	att, err := attest.New()
	a.NoError(err)
	return att.MarshalPublicKey()
}

func TestAddPeer_Success(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	pub := newTestPubKey(t)
	b64Key := fingerprint.Base64(pub)

	err := app.AddPeer(b64Key, "alice")
	a.NoError(err)

	list := app.ListKnownPeers()
	a.Len(list, 1)
	a.Equal("alice", list[0].Name)
	a.Equal(b64Key, list[0].PublicKeyBase64)
	decoded, err := base64.RawURLEncoding.DecodeString(list[0].PublicKeyBase64)
	a.NoError(err)
	a.Equal(pub, decoded, "base64 should round-trip to the same bytes")
	a.False(list[0].FirstSeen.IsZero())
	a.False(list[0].LastSeen.IsZero())
	a.NotEmpty(list[0].FingerprintEmoji)
}

func TestAddPeer_DefaultsNameFromFingerprint(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	pub := newTestPubKey(t)
	b64Key := fingerprint.Base64(pub)

	err := app.AddPeer(b64Key, "")
	a.NoError(err)

	list := app.ListKnownPeers()
	a.Len(list, 1)
	a.NotEmpty(list[0].Name, "name should default to fingerprint pseudonym")
}

func TestAddPeer_InvalidBase64(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	err := app.AddPeer("not-base64-!!!", "alice")
	a.Error(err)
	a.Contains(err.Error(), "decode base64")
}

func TestAddPeer_WrongLength(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	// Too short — 16 bytes instead of 44.
	short := fingerprint.Base64(make([]byte, 16))
	err := app.AddPeer(short, "alice")
	a.Error(err)
	a.Contains(err.Error(), "44 bytes")

	// Too long — 64 bytes.
	long := fingerprint.Base64(make([]byte, 64))
	err = app.AddPeer(long, "alice")
	a.Error(err)
	a.Contains(err.Error(), "44 bytes")
}

func TestAddPeer_Empty(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	err := app.AddPeer("", "alice")
	a.Error(err)
	a.Contains(err.Error(), "required")
}

func TestAddPeer_DuplicateRejected(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	pub := newTestPubKey(t)
	b64Key := fingerprint.Base64(pub)

	a.NoError(app.AddPeer(b64Key, "alice"))
	err := app.AddPeer(b64Key, "alice2")
	a.Error(err)
	a.Contains(err.Error(), "already exists")
}

func TestListKnownPeers_SortedByLastSeen(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
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
	a.NoError(app.AddPeer(b64s[0], names[0]))
	time.Sleep(20 * time.Millisecond)
	a.NoError(app.AddPeer(b64s[1], names[1]))
	time.Sleep(20 * time.Millisecond)
	a.NoError(app.AddPeer(b64s[2], names[2]))

	list := app.ListKnownPeers()
	a.Len(list, 3)
	a.Equal("third", list[0].Name, "most recent first")
	a.Equal("second", list[1].Name)
	a.Equal("first", list[2].Name, "oldest last")
}

func TestGetPeer_Success(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	pub := newTestPubKey(t)
	b64Key := fingerprint.Base64(pub)
	a.NoError(app.AddPeer(b64Key, "alice"))

	got, err := app.GetPeer(b64Key)
	a.NoError(err)
	a.Equal("alice", got.Name)
	a.Equal(b64Key, got.PublicKeyBase64)
}

func TestGetPeer_NotFound(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	pub := newTestPubKey(t)
	b64Key := fingerprint.Base64(pub)

	_, err := app.GetPeer(b64Key)
	a.Error(err)
	a.Contains(err.Error(), "not found")
}

func TestGetPeer_InvalidBase64(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	_, err := app.GetPeer("zz!!!")
	a.Error(err)
}

func TestDeletePeer_Success(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	pub := newTestPubKey(t)
	b64Key := fingerprint.Base64(pub)
	a.NoError(app.AddPeer(b64Key, "alice"))
	a.Len(app.ListKnownPeers(), 1)

	err := app.DeletePeer(b64Key)
	a.NoError(err)
	a.Empty(app.ListKnownPeers(), "peer should be gone after delete")
}

func TestDeletePeer_NotFound(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	pub := newTestPubKey(t)
	b64Key := fingerprint.Base64(pub)

	// The underlying storage layer is a no-op when the peer does not
	// exist. The bus's DeletePeer mirrors that — deleting an
	// unknown peer succeeds (it just doesn't change anything) and
	// the cache refresh is still triggered.
	err := app.DeletePeer(b64Key)
	a.NoError(err)
	a.Empty(app.ListKnownPeers())
}

func TestDeletePeer_InvalidBase64(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	err := app.DeletePeer("not-base64-!!!")
	a.Error(err)
}

func TestRenamePeer_Success(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	pub := newTestPubKey(t)
	b64Key := fingerprint.Base64(pub)
	a.NoError(app.AddPeer(b64Key, "alice"))

	before, err := app.GetPeer(b64Key)
	a.NoError(err)
	originalFirstSeen := before.FirstSeen
	originalLastSeen := before.LastSeen

	a.NoError(app.RenamePeer(b64Key, "alice-renamed"))

	after, err := app.GetPeer(b64Key)
	a.NoError(err)
	a.Equal("alice-renamed", after.Name)
	a.Equal(b64Key, after.PublicKeyBase64)
	a.True(after.FirstSeen.Equal(originalFirstSeen), "FirstSeen should be preserved across rename")
	a.True(after.LastSeen.Equal(originalLastSeen), "LastSeen should be preserved across rename")
}

func TestRenamePeer_TrimsWhitespace(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	pub := newTestPubKey(t)
	b64Key := fingerprint.Base64(pub)
	a.NoError(app.AddPeer(b64Key, "alice"))

	a.NoError(app.RenamePeer(b64Key, "  bob  "))

	got, err := app.GetPeer(b64Key)
	a.NoError(err)
	a.Equal("bob", got.Name)
}

func TestRenamePeer_EmptyRejected(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	pub := newTestPubKey(t)
	b64Key := fingerprint.Base64(pub)
	a.NoError(app.AddPeer(b64Key, "alice"))

	err := app.RenamePeer(b64Key, "")
	a.Error(err)

	err = app.RenamePeer(b64Key, "   ")
	a.Error(err)
}

func TestRenamePeer_NotFound(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	pub := newTestPubKey(t)
	b64Key := fingerprint.Base64(pub)

	err := app.RenamePeer(b64Key, "newname")
	a.Error(err)
	a.Contains(err.Error(), "not found")
}

func TestRenamePeer_InvalidBase64(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	err := app.RenamePeer("not-base64-!!!", "newname")
	a.Error(err)
}

func TestRefreshPeersCache_PicksUpStorePeer(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	// Direct write to the storage layer (simulating a peer arriving
	// through the verifier path, not through AddPeer).
	store := app.store()
	a.NotNil(store)
	pub := newTestPubKey(t)
	peer := &storage.Peer{
		Name:      "via-storage",
		PublicKey: pub,
	}
	a.NoError(store.StorePeer(peer))

	// Cache should not see the new peer until refresh.
	a.Empty(app.ListKnownPeers())

	app.refreshPeersCache()

	list := app.ListKnownPeers()
	a.Len(list, 1)
	a.Equal("via-storage", list[0].Name)
}

func TestRefreshPeersCache_EmptyDB(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	app.refreshPeersCache()
	a.Empty(app.ListKnownPeers())
}

func TestListKnownPeers_DefensiveCopy(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	pub := newTestPubKey(t)
	b64Key := fingerprint.Base64(pub)
	a.NoError(app.AddPeer(b64Key, "alice"))

	list := app.ListKnownPeers()
	a.Len(list, 1)

	// Mutate the returned slice; the cache should be unaffected.
	list[0].Name = "tampered"
	again := app.ListKnownPeers()
	a.Equal("alice", again[0].Name, "cache should be unaffected by external mutation")
}

func TestAddPeer_TrimsWhitespace(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	pub := newTestPubKey(t)
	b64Key := fingerprint.Base64(pub)

	err := app.AddPeer("  "+b64Key+"  \n", "alice")
	a.NoError(err)
	list := app.ListKnownPeers()
	a.Len(list, 1)
	a.Equal(b64Key, list[0].PublicKeyBase64)
}

func TestAddPeer_AcceptsPaddedBase64(t *testing.T) {
	a := require.New(t)
	// Raw URL-safe base64 (the canonical form) has no padding.
	// Go's base64 decoder tolerates either form. Verify the bus
	// accepts both.
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	pub := newTestPubKey(t)
	noPad := fingerprint.Base64(pub)
	padded := fingerprint.Base64(pub) + "=="

	a.NoError(app.AddPeer(padded, "alice"))
	list := app.ListKnownPeers()
	a.Len(list, 1)
	a.Equal(noPad, list[0].PublicKeyBase64,
		"stored base64 should be the canonical un-padded form")
}
