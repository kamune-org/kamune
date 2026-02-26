package kamune

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/pkg/store"
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

// ---------------------------------------------------------------------------
// Session index persistence tests
// ---------------------------------------------------------------------------

func TestSessionIndexSurvivesRestart(t *testing.T) {
	a := assert.New(t)

	f, err := os.CreateTemp("", "kamune-index-restart-*.db")
	a.NoError(err)
	a.NoError(f.Close())
	defer func() { _ = os.Remove(f.Name()) }()

	remotePubKey := []byte("test-remote-public-key-for-index")
	sessionID := "session-index-test-001"

	// First open: create session and register index.
	{
		storage, err := OpenStorage(
			StorageWithDBPath(f.Name()),
			StorageWithAlgorithm(attest.Ed25519Algorithm),
			StorageWithNoPassphrase(),
		)
		a.NoError(err)

		sm := NewSessionManager(storage, 24*time.Hour)

		state := &SessionState{
			SessionID:       sessionID,
			Phase:           PhaseEstablished,
			IsInitiator:     true,
			SharedSecret:    []byte("secret"),
			RemotePublicKey: remotePubKey,
			LocalSalt:       []byte("ls"),
			RemoteSalt:      []byte("rs"),
		}
		a.NoError(sm.SaveSession(state))

		// SaveSession with a RemotePublicKey auto-registers the index.
		sid, ok := sm.GetSessionByPublicKey(remotePubKey)
		a.True(ok)
		a.Equal(sessionID, sid)

		a.NoError(storage.Close())
	}

	// Second open: index should be rebuilt from storage.
	{
		storage, err := OpenStorage(
			StorageWithDBPath(f.Name()),
			StorageWithAlgorithm(attest.Ed25519Algorithm),
			StorageWithNoPassphrase(),
		)
		a.NoError(err)
		defer func() { a.NoError(storage.Close()) }()

		sm := NewSessionManager(storage, 24*time.Hour)

		sid, ok := sm.GetSessionByPublicKey(remotePubKey)
		a.True(ok, "index must survive restart")
		a.Equal(sessionID, sid)

		// Also verify we can load the full session.
		loaded, err := sm.LoadSession(sessionID)
		a.NoError(err)
		a.Equal(PhaseEstablished, loaded.Phase)
		a.Equal(sessionID, loaded.SessionID)
	}
}

func TestSessionIndexUnregister(t *testing.T) {
	a := assert.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	sm := NewSessionManager(storage, 24*time.Hour)
	remotePubKey := []byte("unregister-test-key")
	sessionID := "unregister-session"

	sm.RegisterSession(sessionID, remotePubKey)
	sid, ok := sm.GetSessionByPublicKey(remotePubKey)
	a.True(ok)
	a.Equal(sessionID, sid)

	sm.UnregisterSession(remotePubKey)
	_, ok = sm.GetSessionByPublicKey(remotePubKey)
	a.False(ok)
}

func TestSessionIndexOverwrite(t *testing.T) {
	a := assert.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	sm := NewSessionManager(storage, 24*time.Hour)
	remotePubKey := []byte("overwrite-test-key")

	sm.RegisterSession("session-old", remotePubKey)
	sm.RegisterSession("session-new", remotePubKey)

	sid, ok := sm.GetSessionByPublicKey(remotePubKey)
	a.True(ok)
	a.Equal("session-new", sid, "newer registration must win")
}

func TestSessionIndexMissingKey(t *testing.T) {
	a := assert.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	sm := NewSessionManager(storage, 24*time.Hour)
	_, ok := sm.GetSessionByPublicKey([]byte("does-not-exist"))
	a.False(ok)
}

func TestSessionIndexNilStorage(t *testing.T) {
	a := assert.New(t)
	// SessionManager with nil storage should still work for in-memory ops.
	sm := NewSessionManager(nil, 24*time.Hour)

	remotePubKey := []byte("nil-storage-key")
	sm.RegisterSession("some-session", remotePubKey)

	sid, ok := sm.GetSessionByPublicKey(remotePubKey)
	a.True(ok)
	a.Equal("some-session", sid)

	sm.UnregisterSession(remotePubKey)
	_, ok = sm.GetSessionByPublicKey(remotePubKey)
	a.False(ok)
}

// ---------------------------------------------------------------------------
// SaveSession CreatedAt atomicity tests
// ---------------------------------------------------------------------------

func TestSaveSessionPreservesCreatedAt(t *testing.T) {
	a := assert.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	sm := NewSessionManager(storage, 24*time.Hour)
	sessionID := "created-at-test"

	// First save.
	state := &SessionState{
		SessionID:    sessionID,
		Phase:        PhaseHandshakeAccepted,
		IsInitiator:  true,
		SharedSecret: []byte("secret"),
	}
	a.NoError(sm.SaveSession(state))

	info1, err := sm.GetSessionInfo(sessionID)
	a.NoError(err)
	firstCreated := info1.CreatedAt

	// Small sleep so the second save gets a different timestamp.
	time.Sleep(10 * time.Millisecond)

	// Second save (update phase).
	state.Phase = PhaseEstablished
	a.NoError(sm.SaveSession(state))

	info2, err := sm.GetSessionInfo(sessionID)
	a.NoError(err)
	a.True(info2.CreatedAt.Equal(firstCreated),
		"CreatedAt must be preserved across updates; got %v, want %v",
		info2.CreatedAt, firstCreated)
	a.True(info2.UpdatedAt.After(firstCreated) || info2.UpdatedAt.Equal(firstCreated),
		"UpdatedAt should be >= CreatedAt")
	a.Equal(PhaseEstablished, info2.Phase)
}

func TestSaveSessionInvalidState(t *testing.T) {
	a := assert.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	sm := NewSessionManager(storage, 24*time.Hour)

	a.Error(sm.SaveSession(nil))
	a.Error(sm.SaveSession(&SessionState{}))
	a.Error(sm.SaveSession(&SessionState{SessionID: ""}))
}

// ---------------------------------------------------------------------------
// Batch cleanup tests
// ---------------------------------------------------------------------------

func TestCleanupExpiredSessionsBatch(t *testing.T) {
	a := assert.New(t)

	f, err := os.CreateTemp("", "kamune-cleanup-*.db")
	a.NoError(err)
	a.NoError(f.Close())
	defer func() { _ = os.Remove(f.Name()) }()

	storage, err := OpenStorage(
		StorageWithDBPath(f.Name()),
		StorageWithAlgorithm(attest.Ed25519Algorithm),
		StorageWithNoPassphrase(),
	)
	a.NoError(err)
	defer func() { _ = storage.Close() }()

	// Use a very short timeout so sessions expire immediately.
	sm := NewSessionManager(storage, 1*time.Millisecond)

	// Create several sessions.
	for i := range 5 {
		state := &SessionState{
			SessionID:    "cleanup-" + string(rune('A'+i)),
			Phase:        PhaseEstablished,
			IsInitiator:  true,
			SharedSecret: []byte("s"),
		}
		a.NoError(sm.SaveSession(state))
	}

	// Wait for them to expire.
	time.Sleep(10 * time.Millisecond)

	deleted, err := sm.CleanupExpiredSessions()
	a.NoError(err)
	a.Equal(5, deleted)

	// A second cleanup should find nothing.
	deleted2, err := sm.CleanupExpiredSessions()
	a.NoError(err)
	a.Equal(0, deleted2)
}

func TestCleanupExpiredSessionsNoExpired(t *testing.T) {
	a := assert.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	sm := NewSessionManager(storage, 24*time.Hour)
	state := &SessionState{
		SessionID:    "still-alive",
		Phase:        PhaseEstablished,
		IsInitiator:  false,
		SharedSecret: []byte("s"),
	}
	a.NoError(sm.SaveSession(state))

	deleted, err := sm.CleanupExpiredSessions()
	a.NoError(err)
	a.Equal(0, deleted)

	// Session should still be loadable.
	loaded, err := sm.LoadSession("still-alive")
	a.NoError(err)
	a.Equal("still-alive", loaded.SessionID)
}

// ---------------------------------------------------------------------------
// LoadSessionByPublicKey with persisted index
// ---------------------------------------------------------------------------

func TestLoadSessionByPublicKey(t *testing.T) {
	a := assert.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	sm := NewSessionManager(storage, 24*time.Hour)
	remotePubKey := []byte("load-by-pk-test-key")
	sessionID := "load-by-pk-session"

	state := &SessionState{
		SessionID:       sessionID,
		Phase:           PhaseEstablished,
		IsInitiator:     true,
		SharedSecret:    []byte("secret"),
		RemotePublicKey: remotePubKey,
	}
	a.NoError(sm.SaveSession(state))

	loaded, err := sm.LoadSessionByPublicKey(remotePubKey)
	a.NoError(err)
	a.Equal(sessionID, loaded.SessionID)
	a.Equal(PhaseEstablished, loaded.Phase)
}

func TestLoadSessionByPublicKeyNotFound(t *testing.T) {
	a := assert.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	sm := NewSessionManager(storage, 24*time.Hour)
	_, err := sm.LoadSessionByPublicKey([]byte("nope"))
	a.ErrorIs(err, ErrSessionNotFound)
}

// ---------------------------------------------------------------------------
// UpdateSessionPhase and UpdateSessionSequences (load-modify-save)
// ---------------------------------------------------------------------------

func TestUpdateSessionPhase(t *testing.T) {
	a := assert.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	sm := NewSessionManager(storage, 24*time.Hour)
	state := &SessionState{
		SessionID:    "phase-update-test",
		Phase:        PhaseHandshakeAccepted,
		SharedSecret: []byte("s"),
	}
	a.NoError(sm.SaveSession(state))

	a.NoError(sm.UpdateSessionPhase("phase-update-test", PhaseEstablished))

	loaded, err := sm.LoadSession("phase-update-test")
	a.NoError(err)
	a.Equal(PhaseEstablished, loaded.Phase)
}

func TestUpdateSessionSequences(t *testing.T) {
	a := assert.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	sm := NewSessionManager(storage, 24*time.Hour)
	state := &SessionState{
		SessionID:    "seq-update-test",
		Phase:        PhaseEstablished,
		SharedSecret: []byte("s"),
	}
	a.NoError(sm.SaveSession(state))

	a.NoError(sm.UpdateSessionSequences("seq-update-test", 42, 17))

	loaded, err := sm.LoadSession("seq-update-test")
	a.NoError(err)
	a.Equal(uint64(42), loaded.SendSequence)
	a.Equal(uint64(17), loaded.RecvSequence)
}

// ---------------------------------------------------------------------------
// ListActiveSessions / Stats
// ---------------------------------------------------------------------------

func TestListActiveSessions(t *testing.T) {
	a := assert.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	sm := NewSessionManager(storage, 24*time.Hour)
	for _, id := range []string{"active-1", "active-2", "active-3"} {
		a.NoError(sm.SaveSession(&SessionState{
			SessionID:    id,
			Phase:        PhaseEstablished,
			SharedSecret: []byte("s"),
		}))
	}

	sessions, err := sm.ListActiveSessions()
	a.NoError(err)
	a.Len(sessions, 3)
}

func TestStats(t *testing.T) {
	a := assert.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	sm := NewSessionManager(storage, 24*time.Hour)

	a.NoError(sm.SaveSession(&SessionState{
		SessionID: "stats-1", Phase: PhaseEstablished, SharedSecret: []byte("s"),
	}))
	a.NoError(sm.SaveSession(&SessionState{
		SessionID: "stats-2", Phase: PhaseHandshakeAccepted, SharedSecret: []byte("s"),
	}))

	stats, err := sm.Stats()
	a.NoError(err)
	a.Equal(2, stats.TotalSessions)
	a.Equal(2, stats.ActiveSessions)
	a.Equal(0, stats.ExpiredSessions)
	a.Equal(1, stats.ByPhase[PhaseEstablished])
	a.Equal(1, stats.ByPhase[PhaseHandshakeAccepted])
}

// ---------------------------------------------------------------------------
// DeleteBatch (store level)
// ---------------------------------------------------------------------------

func TestDeleteBatchStore(t *testing.T) {
	a := assert.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	bucket := []byte("test-batch-bucket")
	keys := [][]byte{[]byte("k1"), []byte("k2"), []byte("k3")}

	// Insert keys.
	for _, k := range keys {
		a.NoError(storage.store.Command(func(c storePkg) error {
			return c.AddPlain(bucket, k, []byte("v"))
		}))
	}

	// Batch delete.
	var deleted int
	err := storage.store.Command(func(c storePkg) error {
		var err error
		deleted, err = c.DeleteBatch(bucket, keys)
		return err
	})
	a.NoError(err)
	a.Equal(3, deleted)
}

// storePkg is a type alias used only in tests to keep the import path out of
// the assertion calls. It embeds the store.Command so that the test can call
// AddPlain / DeleteBatch directly.
type storePkg = store.Command

// ---------------------------------------------------------------------------
// CanResume
// ---------------------------------------------------------------------------

func TestCanResumeSession(t *testing.T) {
	a := assert.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	sm := NewSessionManager(storage, 24*time.Hour)

	a.NoError(sm.SaveSession(&SessionState{
		SessionID:    "resumable",
		Phase:        PhaseEstablished,
		SharedSecret: []byte("secret"),
	}))

	ok, phase, err := sm.CanResume("resumable")
	a.NoError(err)
	a.True(ok)
	a.Equal(PhaseEstablished, phase)
}

func TestCanResumeNotEstablished(t *testing.T) {
	a := assert.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	sm := NewSessionManager(storage, 24*time.Hour)

	a.NoError(sm.SaveSession(&SessionState{
		SessionID:    "not-established",
		Phase:        PhaseHandshakeRequested,
		SharedSecret: []byte("s"),
	}))

	ok, _, err := sm.CanResume("not-established")
	a.NoError(err)
	a.False(ok)
}

func TestCanResumeNoSecret(t *testing.T) {
	a := assert.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	sm := NewSessionManager(storage, 24*time.Hour)

	a.NoError(sm.SaveSession(&SessionState{
		SessionID: "no-secret",
		Phase:     PhaseEstablished,
	}))

	ok, _, err := sm.CanResume("no-secret")
	a.NoError(err)
	a.False(ok)
}

func TestCanResumeMissing(t *testing.T) {
	a := assert.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	sm := NewSessionManager(storage, 24*time.Hour)

	ok, _, err := sm.CanResume("does-not-exist")
	a.NoError(err)
	a.False(ok)
}

// ---------------------------------------------------------------------------
// DeleteSession
// ---------------------------------------------------------------------------

func TestDeleteSession(t *testing.T) {
	a := assert.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	sm := NewSessionManager(storage, 24*time.Hour)

	a.NoError(sm.SaveSession(&SessionState{
		SessionID:    "to-delete",
		Phase:        PhaseEstablished,
		SharedSecret: []byte("s"),
	}))

	a.NoError(sm.DeleteSession("to-delete"))

	_, err := sm.LoadSession("to-delete")
	a.Error(err)
}

// ---------------------------------------------------------------------------
// Expired session auto-deletion on LoadSession
// ---------------------------------------------------------------------------

func TestLoadSessionDeletesExpired(t *testing.T) {
	a := assert.New(t)

	f, err := os.CreateTemp("", "kamune-expired-load-*.db")
	a.NoError(err)
	a.NoError(f.Close())
	defer func() { _ = os.Remove(f.Name()) }()

	storage, err := OpenStorage(
		StorageWithDBPath(f.Name()),
		StorageWithAlgorithm(attest.Ed25519Algorithm),
		StorageWithNoPassphrase(),
	)
	a.NoError(err)
	defer func() { _ = storage.Close() }()

	sm := NewSessionManager(storage, 1*time.Millisecond)

	a.NoError(sm.SaveSession(&SessionState{
		SessionID:    "expire-on-load",
		Phase:        PhaseEstablished,
		SharedSecret: []byte("s"),
	}))

	time.Sleep(10 * time.Millisecond)

	_, err = sm.LoadSession("expire-on-load")
	a.ErrorIs(err, ErrSessionExpired)

	// A second load should return a storage-level not-found error, confirming
	// the expired session was cleaned up.
	_, err = sm.LoadSession("expire-on-load")
	a.Error(err)
}

// ---------------------------------------------------------------------------
// GetSessionInfo
// ---------------------------------------------------------------------------

func TestGetSessionInfo(t *testing.T) {
	a := assert.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	sm := NewSessionManager(storage, 24*time.Hour)

	a.NoError(sm.SaveSession(&SessionState{
		SessionID:    "info-test",
		Phase:        PhaseEstablished,
		IsInitiator:  true,
		SharedSecret: []byte("s"),
		SendSequence: 10,
		RecvSequence: 5,
	}))

	info, err := sm.GetSessionInfo("info-test")
	a.NoError(err)
	a.Equal("info-test", info.SessionID)
	a.Equal(PhaseEstablished, info.Phase)
	a.True(info.IsInitiator)
	a.Equal(uint64(10), info.SendSequence)
	a.Equal(uint64(5), info.RecvSequence)
	a.False(info.IsExpired)
	a.False(info.CreatedAt.IsZero())
	a.False(info.UpdatedAt.IsZero())
}
