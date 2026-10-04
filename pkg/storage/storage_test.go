package storage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"

	"github.com/kamune-org/kamune/internal/clock"
	"github.com/kamune-org/kamune/internal/engine"
	"github.com/kamune-org/kamune/pkg/attest"
)

func newTestStorage(t *testing.T) (*Storage, func()) {
	t.Helper()
	a := require.New(t)
	f, err := os.CreateTemp("", "kamune-storage-test-*.db")
	a.NoError(err)
	a.NoError(f.Close())

	storage, err := OpenStorage(
		WithDBPath(f.Name()),
		WithNoPassphrase(),
		WithExpiryDuration(24*time.Hour),
	)
	a.NoError(err)

	cleanup := func() {
		a.NoError(storage.Close())
		a.NoError(os.Remove(f.Name()))
	}
	return storage, cleanup
}

// TestAttesterConcurrentFirstCalls has several goroutines ask a fresh
// database for its identity at once and checks they all get the one that
// is stored.
func TestAttesterConcurrentFirstCalls(t *testing.T) {
	const callers = 16
	for round := range 5 {
		a := require.New(t)
		s, err := OpenStorage(
			WithDBPath(filepath.Join(t.TempDir(), "db")),
			WithNoPassphrase(),
		)
		a.NoError(err)

		var (
			wg    sync.WaitGroup
			start = make(chan struct{})
			keys  = make([][]byte, callers)
			errs  = make([]error, callers)
		)
		for i := range callers {
			wg.Go(func() {
				<-start
				at, err := s.Attester()
				errs[i] = err
				if err == nil {
					keys[i] = at.MarshalPublicKey()
				}
			})
		}
		close(start)
		wg.Wait()

		stored, err := s.PublicKey()
		a.NoError(err)
		for i := range callers {
			a.NoError(errs[i])
			a.Equal(stored, keys[i], "round %d caller %d", round, i)
		}
		a.NoError(s.Close())
	}
}

// ---------------------------------------------------------------------------
// Peer tests
// ---------------------------------------------------------------------------

func TestStorePeerSetsTimestamps(t *testing.T) {
	a := require.New(t)
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
	a := require.New(t)
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
	a := require.New(t)
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
	a := require.New(t)
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
	a := require.New(t)
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
	a := require.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	// Updating a non-existent peer should be a silent no-op.
	err := storage.UpdatePeerLastSeen([]byte("nonexistent"), time.Now())
	a.NoError(err)
}

// TestSessionUpdatesPeerLastSeen checks that a peer's LastSeen follows
// the sessions established and resumed with it, which persist their state
// through PutSessionResumption.
func TestSessionUpdatesPeerLastSeen(t *testing.T) {
	a := require.New(t)
	start := time.Unix(1_700_000_000, 0)
	clk := clock.NewFake(start)
	s, err := OpenStorage(
		WithDBPath(filepath.Join(t.TempDir(), "db")),
		WithNoPassphrase(),
		WithClock(clk),
	)
	a.NoError(err)
	defer s.Close()

	att, err := attest.New()
	a.NoError(err)
	pub := att.MarshalPublicKey()
	a.NoError(s.StorePeer(&Peer{Name: "erin", PublicKey: pub}))

	for _, tc := range []struct {
		name           string
		setEstablished bool
	}{
		{"established", true},
		{"resumed", false},
	} {
		clk.Advance(time.Hour)
		a.NoError(s.PutSessionResumption("sess", pub, nil, tc.setEstablished))
		found, err := s.FindPeer(pub)
		a.NoError(err, tc.name)
		a.True(found.FirstSeen.Equal(start), tc.name)
		a.True(found.LastSeen.Equal(clk.Now()), tc.name)
	}

	// A session with a peer that is not stored does not store it.
	other, err := attest.New()
	a.NoError(err)
	a.NoError(s.PutSessionResumption(
		"other", other.MarshalPublicKey(), nil, true,
	))
	_, err = s.FindPeer(other.MarshalPublicKey())
	a.Error(err)
}

// TestUpdatePeerLastSeenDoesNotRestoreDeletedPeer runs DeletePeer and
// UpdatePeerLastSeen at the same time and checks that the peer is gone
// afterwards, whichever ran first.
func TestUpdatePeerLastSeenDoesNotRestoreDeletedPeer(t *testing.T) {
	a := require.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	att, err := attest.New()
	a.NoError(err)
	pub := att.MarshalPublicKey()
	for round := range 20 {
		a.NoError(storage.StorePeer(&Peer{Name: "frank", PublicKey: pub}))

		var (
			wg                   sync.WaitGroup
			start                = make(chan struct{})
			updateErr, deleteErr error
		)
		wg.Go(func() {
			<-start
			updateErr = storage.UpdatePeerLastSeen(pub, time.Time{})
		})
		wg.Go(func() {
			<-start
			deleteErr = storage.DeletePeer(pub)
		})
		close(start)
		wg.Wait()
		a.NoError(updateErr)
		a.NoError(deleteErr)

		_, err := storage.FindPeer(pub)
		a.Error(err, "round %d: deleted peer came back", round)
	}
}

// TestRemoveExpiredPeerKeepsRestoredPeer finds a peer expired, stores it
// again before the expired record is removed, and checks that the new
// record is kept.
func TestRemoveExpiredPeerKeepsRestoredPeer(t *testing.T) {
	a := require.New(t)
	now := time.Unix(1_700_000_000, 0)
	s, err := OpenStorage(
		WithDBPath(filepath.Join(t.TempDir(), "db")),
		WithNoPassphrase(),
		WithClock(clock.NewFake(now)),
		WithExpiryDuration(time.Hour),
	)
	a.NoError(err)
	defer s.Close()

	att, err := attest.New()
	a.NoError(err)
	pub := att.MarshalPublicKey()
	a.NoError(s.StorePeer(&Peer{
		Name: "old", PublicKey: pub, FirstSeen: now.Add(-2 * time.Hour),
	}))
	a.NoError(s.engine.Query(func(b Namespace) error {
		_, err := s.findPeer(b, s.peerKey(pub))
		a.ErrorIs(err, ErrPeerExpired)
		return nil
	}))

	a.NoError(s.StorePeer(&Peer{Name: "new", PublicKey: pub}))
	s.removeExpiredPeer(s.peerKey(pub))

	found, err := s.FindPeer(pub)
	a.NoError(err)
	a.Equal("new", found.Name)
}

func TestListPeers(t *testing.T) {
	a := require.New(t)
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
	a := require.New(t)

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
	a := require.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	peers, err := storage.ListPeers()
	a.NoError(err)
	a.Empty(peers)
}

func TestDeletePeer(t *testing.T) {
	a := require.New(t)
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

// TestCopiedPeerRecordIsNotTrusted copies a known peer's record to the key
// of an attacker's public key, as someone who can write the database file
// but has no passphrase could, and checks that the attacker is not found
// as a known peer.
func TestCopiedPeerRecordIsNotTrusted(t *testing.T) {
	cases := []struct {
		name string
		// copy puts the record of victim under the key of attacker.
		copy func(t *testing.T, s *Storage, path string, victim, attacker []byte)
		want error
	}{
		{
			// The stored bytes are bound to the victim's key, so the copy
			// does not even decrypt.
			name: "raw ciphertext",
			copy: func(t *testing.T, s *Storage, path string, victim, attacker []byte) {
				a := require.New(t)
				a.NoError(s.Close())
				db, err := bolt.Open(path, 0600, nil)
				a.NoError(err)
				a.NoError(db.Update(func(tx *bolt.Tx) error {
					peers := tx.Bucket([]byte("peers"))
					v := bytes.Clone(peers.Get(s.peerKey(victim)))
					a.NotNil(v)
					return peers.Put(s.peerKey(attacker), v)
				}))
				a.NoError(db.Close())
			},
		},
		{
			// A record that decrypts under the attacker's key, such as one
			// written before values were bound to their location, holds
			// the victim's public key.
			name: "decryptable record",
			copy: func(t *testing.T, s *Storage, path string, victim, attacker []byte) {
				a := require.New(t)
				a.NoError(s.engine.Command(func(b Namespace) error {
					peers := b.Sub([]byte("peers"))
					v, err := peers.GetEncrypted(s.peerKey(victim))
					if err != nil {
						return err
					}
					return peers.PutEncrypted(s.peerKey(attacker), v)
				}))
				a.NoError(s.Close())
			},
			want: ErrPeerMismatch,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			path := filepath.Join(t.TempDir(), "db")
			open := func() *Storage {
				s, err := OpenStorage(WithDBPath(path), WithNoPassphrase())
				a.NoError(err)
				return s
			}
			victim, err := attest.New()
			a.NoError(err)
			attacker, err := attest.New()
			a.NoError(err)
			victimPK := victim.MarshalPublicKey()
			attackerPK := attacker.MarshalPublicKey()

			s := open()
			a.NoError(s.StorePeer(&Peer{Name: "friend", PublicKey: victimPK}))
			tc.copy(t, s, path, victimPK, attackerPK)

			s = open()
			defer s.Close()
			_, err = s.FindPeer(attackerPK)
			a.Error(err, "attacker must not be a known peer")
			if tc.want != nil {
				a.ErrorIs(err, tc.want)
			}
			found, err := s.FindPeer(victimPK)
			a.NoError(err)
			a.Equal("friend", found.Name)

			peers, err := s.ListPeers()
			a.NoError(err)
			a.Len(peers, 1)
			a.Equal(victimPK, peers[0].PublicKey)
		})
	}
}

// ---------------------------------------------------------------------------
// Session tests
// ---------------------------------------------------------------------------

func TestCreateAndGetSession(t *testing.T) {
	a := require.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	att, err := attest.New()
	a.NoError(err)

	a.NoError(storage.StorePeer(&Peer{
		Name:      "alice",
		PublicKey: att.MarshalPublicKey(),
		FirstSeen: time.Now(),
	}))
	before := time.Now()
	a.NoError(storage.CreateSession("sess-1", att.MarshalPublicKey()))

	peer, err := storage.GetPeer("sess-1")
	a.NoError(err)
	a.Equal(att.MarshalPublicKey(), peer.PublicKey)
	a.Equal("alice", peer.Name)

	ts, err := storage.GetEstablishedAt("sess-1")
	a.NoError(err)
	a.False(ts.Before(before))
}

func TestGetSessionPeerNotFound(t *testing.T) {
	a := require.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	_, err := storage.GetPeer("nonexistent")
	a.ErrorIs(err, ErrSessionNotFound)
}

func TestCreateSessionAppearsInListSessions(t *testing.T) {
	a := require.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	att1, err := attest.New()
	a.NoError(err)
	att2, err := attest.New()
	a.NoError(err)

	a.NoError(storage.StorePeer(&Peer{
		Name:      "alice",
		PublicKey: att1.MarshalPublicKey(),
		FirstSeen: time.Now(),
	}))
	a.NoError(storage.StorePeer(&Peer{
		Name:      "bob",
		PublicKey: att2.MarshalPublicKey(),
		FirstSeen: time.Now(),
	}))

	a.NoError(storage.CreateSession("s1", att1.MarshalPublicKey()))
	a.NoError(storage.CreateSession("s2", att2.MarshalPublicKey()))

	sessions, err := storage.ListSessions()
	a.NoError(err)
	a.Contains(sessions, "s1")
	a.Contains(sessions, "s2")
}

func TestDeleteSessionRemovesRecord(t *testing.T) {
	a := require.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	att, err := attest.New()
	a.NoError(err)

	a.NoError(storage.StorePeer(&Peer{
		Name:      "alice",
		PublicKey: att.MarshalPublicKey(),
		FirstSeen: time.Now(),
	}))

	a.NoError(storage.CreateSession("del-me", att.MarshalPublicKey()))

	// Verify it exists.
	_, err = storage.GetPeer("del-me")
	a.NoError(err)

	// Delete it.
	a.NoError(storage.DeleteSession("del-me"))

	// Should be gone.
	_, err = storage.GetPeer("del-me")
	a.ErrorIs(err, ErrSessionNotFound)
}

// rawValues returns every value stored in the bolt file at path, keyed by
// the value itself.
func rawValues(t *testing.T, path string) map[string]bool {
	t.Helper()
	a := require.New(t)
	db, err := bolt.Open(path, 0600, nil)
	a.NoError(err)
	defer db.Close()
	values := map[string]bool{}
	var walk func(b *bolt.Bucket) error
	walk = func(b *bolt.Bucket) error {
		return b.ForEach(func(k, v []byte) error {
			if v == nil {
				return walk(b.Bucket(k))
			}
			values[string(v)] = true
			return nil
		})
	}
	a.NoError(db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(_ []byte, b *bolt.Bucket) error {
			return walk(b)
		})
	}))
	return values
}

// TestDeleteLeavesNoTraceInFile deletes a session with its history and a
// peer, and checks that none of the values they had, nor the session ID,
// are left anywhere in the database file, where bolt would otherwise keep
// them in free pages.
func TestDeleteLeavesNoTraceInFile(t *testing.T) {
	a := require.New(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "db")
	open := func() *Storage {
		s, err := OpenStorage(WithDBPath(path), WithNoPassphrase())
		a.NoError(err)
		return s
	}
	const gone = "QKZDELETEDSESSIONID23456"

	s := open()
	var pubs [][]byte
	for _, name := range []string{"kept", "deleted"} {
		att, err := attest.New()
		a.NoError(err)
		pub := att.MarshalPublicKey()
		pubs = append(pubs, pub)
		a.NoError(s.StorePeer(&Peer{Name: name, PublicKey: pub}))
	}
	a.NoError(s.CreateSession("kept-session", pubs[0]))
	a.NoError(s.CreateSession(gone, pubs[1]))
	for i := range 100 {
		for _, id := range []string{"kept-session", gone} {
			a.NoError(s.AddChatEntry(
				id, fmt.Appendf(nil, "message %d", i), time.Now(),
				SenderPeer,
			))
		}
	}
	a.NoError(s.Close())
	before := rawValues(t, path)

	s = open()
	a.NoError(s.DeleteSession(gone))
	a.NoError(s.DeletePeer(pubs[1]))
	history, err := s.GetChatHistory("kept-session")
	a.NoError(err)
	a.Len(history, 100)
	a.NoError(s.Close())

	after := rawValues(t, path)
	raw, err := os.ReadFile(path)
	a.NoError(err)
	a.NotContains(string(raw), gone)
	deleted := 0
	for v := range before {
		if after[v] {
			continue
		}
		deleted++
		a.False(
			bytes.Contains(raw, []byte(v)),
			"a deleted value is still in the file",
		)
	}
	a.GreaterOrEqual(deleted, 100, "the deleted history and peer")
	entries, err := os.ReadDir(dir)
	a.NoError(err)
	a.Len(entries, 2, "only the database and its lock file")
}

func TestAddChatEntryToCreatedSession(t *testing.T) {
	a := require.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	att, err := attest.New()
	a.NoError(err)
	a.NoError(storage.StorePeer(&Peer{
		Name:      "alice",
		PublicKey: att.MarshalPublicKey(),
		FirstSeen: time.Now(),
	}))

	a.NoError(storage.CreateSession("auto-sess", att.MarshalPublicKey()))
	a.NoError(storage.AddChatEntry(
		"auto-sess", []byte("hello"), time.Now(), SenderLocal,
	))

	entries, err := storage.GetChatHistory("auto-sess")
	a.NoError(err)
	a.Len(entries, 1)
	a.Equal([]byte("hello"), entries[0].Data)
}

// TestAddChatEntryWithoutCreateSession stores messages in sessions that
// CreateSession never ran for, such as one accepted while incognito or
// whose peer record expired.
func TestAddChatEntryWithoutCreateSession(t *testing.T) {
	cases := []struct {
		name  string
		setup func(a *require.Assertions, s *Storage, id string)
	}{
		{"no session", func(*require.Assertions, *Storage, string) {}},
		{"resumption state only", func(a *require.Assertions, s *Storage, id string) {
			att, err := attest.New()
			a.NoError(err)
			a.NoError(s.PutSessionResumption(
				id, att.MarshalPublicKey(), nil, true,
			))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			store, cleanup := newTestStorage(t)
			defer cleanup()
			tc.setup(a, store, "sess")

			a.NoError(store.AddChatEntry(
				"sess", []byte("hello"), time.Now(), SenderPeer,
			))
			entries, err := store.GetChatHistory("sess")
			a.NoError(err)
			a.Len(entries, 1)
			a.Equal([]byte("hello"), entries[0].Data)
		})
	}
}

func TestGetChatHistorySupportsLegacyAndMalformedEntries(t *testing.T) {
	a := require.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	legacyTime := time.Unix(0, 100)
	versionedTime := time.Unix(0, 200)
	a.NoError(storage.engine.Command(func(b Namespace) error {
		chat := ensureChat(a, storage, b, "mixed")

		legacyKey := chatKey(legacyTime, SenderLocal, 1)
		if err := chat.PutEncrypted(legacyKey, []byte("legacy")); err != nil {
			return err
		}

		versionedValue := append([]byte{}, valueMagic...)
		var timestamp [8]byte
		binary.BigEndian.PutUint64(
			timestamp[:],
			uint64(versionedTime.UnixNano()),
		)
		versionedValue = append(versionedValue, timestamp[:]...)
		versionedValue = append(versionedValue, []byte("versioned")...)
		if err := chat.PutEncrypted(
			chatKey(time.Unix(0, 300), SenderPeer, 2), versionedValue,
		); err != nil {
			return err
		}

		truncated := append([]byte{}, valueMagic...)
		truncated = append(truncated, 1, 2)
		return chat.PutEncrypted(
			chatKey(time.Unix(0, 400), SenderPeer, 3),
			truncated,
		)
	}))

	entries, err := storage.GetChatHistory("mixed")
	a.NoError(err)
	a.Equal([]ChatEntry{
		{
			Timestamp: legacyTime,
			Data:      []byte("legacy"),
			Sender:    SenderLocal,
		},
		{
			Timestamp: time.Unix(0, 300),
			SentAt:    versionedTime,
			Data:      []byte("versioned"),
			Sender:    SenderPeer,
		},
	}, entries)
}

// TestGetChatHistoryIgnoresSenderTimestampForOrder stores a peer reply
// whose sender timestamp claims it came before the local question, and
// checks that history keeps the order the messages were stored in.
func TestGetChatHistoryIgnoresSenderTimestampForOrder(t *testing.T) {
	a := require.New(t)
	start := time.Date(2026, 1, 2, 22, 14, 21, 0, time.UTC)
	clk := clock.NewFake(start)
	s, err := OpenStorage(
		WithDBPath(filepath.Join(t.TempDir(), "db")),
		WithNoPassphrase(),
		WithClock(clk),
	)
	a.NoError(err)
	defer s.Close()

	att, err := attest.New()
	a.NoError(err)
	a.NoError(s.StorePeer(&Peer{Name: "peer", PublicKey: att.MarshalPublicKey()}))
	a.NoError(s.CreateSession("sess", att.MarshalPublicKey()))

	a.NoError(s.AddChatEntry(
		"sess", []byte("should I wire the money?"), start, SenderLocal,
	))
	clk.Advance(time.Second)
	forged := start.Add(-time.Hour)
	a.NoError(s.AddChatEntry("sess", []byte("NO"), forged, SenderPeer))

	entries, err := s.GetChatHistory("sess")
	a.NoError(err)
	a.Len(entries, 2)
	a.Equal([]byte("should I wire the money?"), entries[0].Data)
	a.Equal([]byte("NO"), entries[1].Data)
	a.True(entries[1].Timestamp.Equal(start.Add(time.Second)))
	a.True(entries[1].SentAt.Equal(forged))
}

// TestSessionMessageCount checks that session summaries take their message
// count from the counter AddChatEntry keeps, and that sessions written
// before the counter existed are counted and then get one.
func TestSessionMessageCount(t *testing.T) {
	a := require.New(t)
	store, cleanup := newTestStorage(t)
	defer cleanup()
	counter := func(id string) []byte {
		m, err := store.GetMeta(id, messageCountKey)
		a.NoError(err)
		return m.Value()
	}
	be := func(n uint64) []byte {
		return binary.BigEndian.AppendUint64(nil, n)
	}

	for range 3 {
		a.NoError(store.AddChatEntry(
			"new", []byte("m"), time.Now(), SenderLocal,
		))
	}
	a.Equal(be(3), counter("new"))
	_, _, count, err := store.SessionTimestamps("new")
	a.NoError(err)
	a.Equal(3, count)

	// The count is read from the counter, not by walking the bucket.
	a.NoError(store.SetMeta("new", NewBytesMeta(messageCountKey, be(42))))
	_, _, count, err = store.SessionTimestamps("new")
	a.NoError(err)
	a.Equal(42, count)

	// A session stored without a counter is counted, and listing the
	// sessions stores its counter.
	a.NoError(store.engine.Command(func(b Namespace) error {
		chat := ensureChat(a, store, b, "old")
		for i := range 5 {
			err := chat.PutEncrypted(
				chatKey(time.Unix(0, int64(i+1)), SenderPeer, 1), []byte("m"),
			)
			if err != nil {
				return err
			}
		}
		return nil
	}))
	a.Nil(counter("old"))
	_, _, count, err = store.SessionTimestamps("old")
	a.NoError(err)
	a.Equal(5, count)

	summaries, err := store.ListSessionsByRecent()
	a.NoError(err)
	counts := map[string]int{}
	for _, sum := range summaries {
		counts[sum.ID] = sum.MessageCount
	}
	a.Equal(map[string]int{"new": 42, "old": 5}, counts)
	a.Equal(be(5), counter("old"))

	a.NoError(store.AddChatEntry("old", []byte("m"), time.Now(), SenderPeer))
	a.Equal(be(6), counter("old"))
}

// chatBuckets calls fn with every chat bucket of every session in the bolt
// file at path.
func chatBuckets(t *testing.T, path string, fn func(chat *bolt.Bucket)) {
	t.Helper()
	a := require.New(t)
	db, err := bolt.Open(path, 0600, nil)
	a.NoError(err)
	defer db.Close()
	a.NoError(db.View(func(tx *bolt.Tx) error {
		sessions := tx.Bucket([]byte("sessions"))
		return sessions.ForEach(func(name, _ []byte) error {
			if chat := sessions.Bucket(name).Bucket([]byte("chat")); chat != nil {
				fn(chat)
			}
			return nil
		})
	}))
}

// TestChatEntriesHideTimeSenderAndLength stores messages of different
// lengths from both sides and checks that the keys hold only their order,
// that short messages are stored at the same length, and that the receive
// times are not in the file.
func TestChatEntriesHideTimeSenderAndLength(t *testing.T) {
	a := require.New(t)
	path := filepath.Join(t.TempDir(), "db")
	start := time.Date(2026, 10, 3, 22, 15, 24, 994172782, time.UTC)
	clk := clock.NewFake(start)
	s, err := OpenStorage(
		WithDBPath(path), WithNoPassphrase(), WithClock(clk),
	)
	a.NoError(err)

	messages := []struct {
		data   []byte
		sender Sender
	}{
		{[]byte("yes"), SenderLocal},
		{[]byte("no thanks, maybe some other time"), SenderPeer},
		{bytes.Repeat([]byte("long "), 120), SenderPeer},
	}
	var times [][]byte
	for _, m := range messages {
		times = append(times, binary.BigEndian.AppendUint64(
			nil, uint64(clk.Now().UnixNano()),
		))
		a.NoError(s.AddChatEntry("sess", m.data, start, m.sender))
		clk.Advance(1234 * time.Millisecond)
	}
	history, err := s.GetChatHistory("sess")
	a.NoError(err)
	a.Len(history, len(messages))
	for i, m := range messages {
		a.Equal(m.data, history[i].Data)
		a.Equal(m.sender, history[i].Sender)
		a.True(history[i].SentAt.Equal(start))
		a.Equal(times[i], binary.BigEndian.AppendUint64(
			nil, uint64(history[i].Timestamp.UnixNano()),
		))
	}
	a.NoError(s.Close())

	var keys [][]byte
	var lengths []int
	chatBuckets(t, path, func(chat *bolt.Bucket) {
		a.NoError(chat.ForEach(func(k, v []byte) error {
			keys = append(keys, bytes.Clone(k))
			lengths = append(lengths, len(v))
			return nil
		}))
	})
	a.Equal([][]byte{
		{0xff, 0, 0, 0, 0, 0, 0, 0, 0},
		{0xff, 0, 0, 0, 0, 0, 0, 0, 1},
		{0xff, 0, 0, 0, 0, 0, 0, 0, 2},
	}, keys)
	a.Equal(lengths[0], lengths[1], "short messages differ in length")
	a.Greater(lengths[2], lengths[1])

	raw, err := os.ReadFile(path)
	a.NoError(err)
	for i, ts := range times {
		a.False(bytes.Contains(raw, ts), "receive time %d in file", i)
	}
}

// ensureChat returns the chat namespace of session id, creating the
// session as this version stores it.
func ensureChat(a *require.Assertions, s *Storage, b Namespace, id string) Namespace {
	session, err := s.ensureSession(b, id)
	a.NoError(err)
	return session.Ensure([]byte("chat"))
}

// putLegacyEntries stores entries in chat as versions before index keys
// did.
func putLegacyEntries(chat Namespace, entries []ChatEntry) error {
	for i, e := range entries {
		value := e.Data
		if !e.SentAt.IsZero() {
			value = binary.BigEndian.AppendUint64(
				bytes.Clone(valueMagic), uint64(e.SentAt.UnixNano()),
			)
			value = append(value, e.Data...)
		}
		err := chat.PutEncrypted(
			chatKey(e.Timestamp, e.Sender, uint32(i)), value,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

// writeLegacyChat stores entries in session id as versions before index
// keys and keyed names did, and marks the database as written by them.
// The database must be opened again to see them.
func writeLegacyChat(t *testing.T, s *Storage, id string, entries []ChatEntry) {
	t.Helper()
	a := require.New(t)
	a.NoError(s.engine.Command(func(b Namespace) error {
		if err := b.Sub([]byte(engine.DefaultNamespace)).Delete(
			[]byte(formatKey),
		); err != nil {
			return err
		}
		chat := b.Ensure([]byte("sessions")).
			Ensure([]byte(id)).
			Ensure([]byte("chat"))
		return putLegacyEntries(chat, entries)
	}))
}

// TestOpenStorageConvertsLegacyChat opens a database whose history was
// stored under keys that hold the receive time and sender, and checks
// that it reads the same afterwards, with neither those keys nor their
// times left in the file.
func TestOpenStorageConvertsLegacyChat(t *testing.T) {
	a := require.New(t)
	path := filepath.Join(t.TempDir(), "db")
	open := func() *Storage {
		s, err := OpenStorage(WithDBPath(path), WithNoPassphrase())
		a.NoError(err)
		return s
	}
	base := time.Unix(1_790_000_000, 0)
	// In the order history had them: by receive time, then sender.
	legacy := []ChatEntry{
		{Timestamp: base, Data: []byte("raw"), Sender: SenderLocal},
		{
			Timestamp: base.Add(time.Second),
			SentAt:    base,
			Data:      []byte("same time, local"),
			Sender:    SenderLocal,
		},
		{
			Timestamp: base.Add(time.Second),
			SentAt:    base.Add(-time.Hour),
			Data:      []byte("versioned"),
			Sender:    SenderPeer,
		},
	}

	s := open()
	writeLegacyChat(t, s, "old", legacy)
	a.NoError(s.Close())

	s = open()
	after, err := s.GetChatHistory("old")
	a.NoError(err)
	a.Equal(legacy, after)
	first, last, count, err := s.SessionTimestamps("old")
	a.NoError(err)
	a.True(first.Equal(base))
	a.True(last.Equal(base.Add(time.Second)))
	a.Equal(3, count)
	a.NoError(s.AddChatEntry("old", []byte("new"), base, SenderPeer))
	a.NoError(s.Close())

	raw, err := os.ReadFile(path)
	a.NoError(err)
	for i, e := range legacy {
		key := chatKey(e.Timestamp, e.Sender, uint32(i))
		a.False(bytes.Contains(raw, key[:8]), "legacy key %d in file", i)
	}
	chatBuckets(t, path, func(chat *bolt.Bucket) {
		a.Equal(4, chat.Stats().KeyN)
		a.NoError(chat.ForEach(func(k, _ []byte) error {
			a.True(isChatIndexKey(k), "key %x", k)
			return nil
		}))
	})
	s = open()
	defer s.Close()
	after, err = s.GetChatHistory("old")
	a.NoError(err)
	a.Equal(append(legacy, after[3]), after)
	a.Equal([]byte("new"), after[3].Data)
}

func TestOpenStorageRejectsNewerFormat(t *testing.T) {
	a := require.New(t)
	path := filepath.Join(t.TempDir(), "db")
	s, err := OpenStorage(WithDBPath(path), WithNoPassphrase())
	a.NoError(err)
	a.NoError(s.engine.Command(func(b Namespace) error {
		return b.Sub([]byte(engine.DefaultNamespace)).PutEncrypted(
			[]byte(formatKey), []byte{storageFormat + 1},
		)
	}))
	a.NoError(s.Close())

	_, err = OpenStorage(WithDBPath(path), WithNoPassphrase())
	a.ErrorIs(err, ErrUnsupportedFormat)
	// The failed open released the database.
	s, err = OpenStorage(
		WithDBPath(path), WithNoPassphrase(), WithTimeout(time.Second),
	)
	a.ErrorIs(err, ErrUnsupportedFormat)
	a.Nil(s)
}

// TestAddChatEntryConvertsLegacyEntries stores a message in a session
// that still has entries under legacy keys, and checks that they are
// converted, a malformed one dropped, and the new one stored last.
func TestAddChatEntryConvertsLegacyEntries(t *testing.T) {
	a := require.New(t)
	store, cleanup := newTestStorage(t)
	defer cleanup()
	base := time.Unix(1_700_000_000, 0)
	a.NoError(store.engine.Command(func(b Namespace) error {
		chat := ensureChat(a, store, b, "sess")
		err := putLegacyEntries(chat, []ChatEntry{
			{Timestamp: base, Data: []byte("one"), Sender: SenderPeer},
			{Timestamp: base.Add(time.Second), Data: []byte("two")},
		})
		if err != nil {
			return err
		}
		return chat.PutEncrypted(
			chatKey(base.Add(2*time.Second), SenderPeer, 9),
			append(bytes.Clone(valueMagic), 1, 2),
		)
	}))
	_, _, count, err := store.SessionTimestamps("sess")
	a.NoError(err)
	a.Equal(3, count)

	a.NoError(store.AddChatEntry("sess", []byte("three"), base, SenderLocal))
	history, err := store.GetChatHistory("sess")
	a.NoError(err)
	var got []string
	for _, e := range history {
		got = append(got, string(e.Data))
	}
	a.Equal([]string{"one", "two", "three"}, got)
	_, _, count, err = store.SessionTimestamps("sess")
	a.NoError(err)
	a.Equal(3, count)
	a.NoError(store.engine.Query(func(b Namespace) error {
		chat := store.sessionChat(b, "sess")
		a.Equal(chatIndexKey(0), chat.FirstKey())
		a.Equal(chatIndexKey(2), chat.LastKey())
		return nil
	}))
}

func chatKey(timestamp time.Time, sender Sender, suffix uint32) []byte {
	key := make([]byte, 14)
	binary.BigEndian.PutUint64(key[:8], uint64(timestamp.UnixNano()))
	binary.BigEndian.PutUint16(key[8:10], uint16(sender))
	binary.BigEndian.PutUint32(key[10:], suffix)
	return key
}

func FuzzDecodeChatEntry(f *testing.F) {
	legacyKey := chatKey(time.Unix(0, 100), SenderLocal, 1)
	versionedKey := chatKey(time.Unix(0, 200), SenderPeer, 2)
	versionedValue := append([]byte{}, valueMagic...)
	var timestamp [8]byte
	binary.BigEndian.PutUint64(timestamp[:], 300)
	versionedValue = append(versionedValue, timestamp[:]...)
	versionedValue = append(versionedValue, []byte("versioned")...)

	f.Add([]byte{}, []byte{})
	f.Add(legacyKey, []byte("legacy"))
	f.Add(versionedKey, versionedValue)
	f.Add(versionedKey, append([]byte{}, valueMagic...))
	indexed := encodeChatValue(ChatEntry{
		Timestamp: time.Unix(0, 400),
		SentAt:    time.Unix(0, 300),
		Data:      []byte("indexed"),
		Sender:    SenderPeer,
	})
	f.Add(chatIndexKey(7), indexed)
	f.Add(chatIndexKey(7), indexed[:chatHeaderSize])
	f.Add(chatIndexKey(7), []byte("legacy"))

	f.Fuzz(func(t *testing.T, key, value []byte) {
		if len(key) > 1024 || len(value) > 64*1024 {
			t.Skip()
		}
		a := require.New(t)
		entry, ok := decodeChatEntry(key, value)
		switch {
		case len(key) == 9 && key[0] == 0xff:
			n := -1
			if len(value) >= 27 {
				n = int(binary.BigEndian.Uint32(value[23:27]))
			}
			if !bytes.HasPrefix(value, []byte("KMNE\x02")) || n < 0 ||
				n > len(value)-27 {
				a.False(ok)
				return
			}
			a.True(ok)
			a.Equal(
				time.Unix(0, int64(binary.BigEndian.Uint64(value[5:13]))),
				entry.Timestamp,
			)
			var wantSentAt time.Time
			if v := int64(binary.BigEndian.Uint64(value[13:21])); v != 0 {
				wantSentAt = time.Unix(0, v)
			}
			a.Equal(wantSentAt, entry.SentAt)
			a.Equal(Sender(binary.BigEndian.Uint16(value[21:23])), entry.Sender)
			want := bytes.Clone(value[27 : 27+n])
			a.Equal(want, entry.Data)
			// The entry does not share memory with the value.
			if n > 0 {
				value[27] ^= 0xff
				a.Equal(want, entry.Data)
			}
			a.Equal(entry, func() ChatEntry {
				e, ok := decodeChatValue(encodeChatValue(entry))
				a.True(ok)
				return e
			}())
		case len(key) < 14:
			a.False(ok)
		case bytes.HasPrefix(value, valueMagic) &&
			len(value) < len(valueMagic)+8:
			a.False(ok)
		default:
			a.True(ok)
			a.Equal(Sender(binary.BigEndian.Uint16(key[8:10])), entry.Sender)

			wantTimestamp := int64(binary.BigEndian.Uint64(key[:8]))
			var wantSentAt time.Time
			wantData := value
			if bytes.HasPrefix(value, valueMagic) {
				offset := len(valueMagic)
				wantSentAt = time.Unix(0, int64(binary.BigEndian.Uint64(value[offset:offset+8])))
				wantData = value[offset+8:]
			}
			wantData = bytes.Clone(wantData)
			a.Equal(time.Unix(0, wantTimestamp), entry.Timestamp)
			a.Equal(wantSentAt, entry.SentAt)
			a.Equal(wantData, entry.Data)

			if len(value) > 0 {
				value[len(value)-1] ^= 0xff
				a.Equal(wantData, entry.Data)
			}
		}
	})
}

func FuzzPackedListCodec(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0})
	f.Add([]byte{0, 0, 0, 0})
	f.Add(serializeList([][]byte{make([]byte, ElemSize)}))
	f.Add(serializeList([][]byte{make([]byte, ElemSize), bytes.Repeat([]byte{0xff}, ElemSize)}))
	f.Add([]byte{0, 0, 0, 1})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64*1024 {
			t.Skip()
		}
		a := require.New(t)

		decoded, err := deserializeList(data)
		if len(data) < 4 {
			a.NoError(err)
			a.Nil(decoded)
		} else {
			count := uint64(binary.BigEndian.Uint32(data[:4]))
			expected := uint64(4) + count*uint64(ElemSize)
			if expected != uint64(len(data)) {
				a.ErrorIs(err, ErrNotFound)
				a.Nil(decoded)
			} else {
				a.NoError(err)
				a.Len(decoded, int(count))
				a.Equal(data, serializeList(decoded))
			}
		}

		payloadSize := len(data) - len(data)%ElemSize
		items := make([][]byte, 0, payloadSize/ElemSize)
		for offset := 0; offset < payloadSize; offset += ElemSize {
			items = append(items, data[offset:offset+ElemSize])
		}
		encoded := serializeList(items)
		roundTrip, err := deserializeList(encoded)
		a.NoError(err)
		a.Equal(items, roundTrip)
	})
}

// ---------------------------------------------------------------------------
// Resumption token tests
// ---------------------------------------------------------------------------

func makeToken(n byte, size int) []byte {
	t := make([]byte, size)
	for i := range t {
		t[i] = n
	}
	return t
}

func TestStoreAndRetrieveResumptionTokens(t *testing.T) {
	a := require.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	att, err := attest.New()
	a.NoError(err)
	a.NoError(storage.StorePeer(&Peer{
		Name:      "alice",
		PublicKey: att.MarshalPublicKey(),
		FirstSeen: time.Now(),
	}))
	a.NoError(storage.CreateSession("sess-tok", att.MarshalPublicKey()))

	tokens := make([][]byte, 20)
	for i := range tokens {
		tokens[i] = makeToken(byte(i), 32)
	}
	err = storage.SetMeta("sess-tok", NewByteSlicesMeta(ResumptionTokensKey, tokens))
	a.NoError(err)

	// Pop returns the first entry.
	tok, err := storage.PopList(
		"sess-tok", ResumptionTokensKey,
	)
	a.NoError(err)
	a.Equal(tokens[0], tok)

	// Second pop gets a different entry.
	tok2, err := storage.PopList(
		"sess-tok", ResumptionTokensKey,
	)
	a.NoError(err)
	a.NotNil(tok2)
	a.NotEqual(tokens[0], tok2)
}

func TestPopSessionToken_Sequential(t *testing.T) {
	a := require.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	att, err := attest.New()
	a.NoError(err)
	a.NoError(storage.StorePeer(&Peer{
		Name:      "bob",
		PublicKey: att.MarshalPublicKey(),
		FirstSeen: time.Now(),
	}))
	a.NoError(storage.CreateSession("sess-seq", att.MarshalPublicKey()))

	tokens := make([][]byte, 3)
	for i := range tokens {
		tokens[i] = makeToken(byte(i+10), 32)
	}
	err = storage.SetMeta("sess-seq", NewByteSlicesMeta(ResumptionTokensKey, tokens))
	a.NoError(err)

	// Pop all three in order.
	for i := 0; i < 3; i++ {
		tok, err := storage.PopList(
			"sess-seq", ResumptionTokensKey,
		)
		a.NoError(err)
		a.Equal(tokens[i], tok)
	}

	// Fourth call returns empty list.
	_, err = storage.PopList("sess-seq", ResumptionTokensKey)
	a.ErrorIs(err, ErrNotFound)
}

func TestRemoveSessionToken_RemovesCorrectToken(t *testing.T) {
	a := require.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	att, err := attest.New()
	a.NoError(err)
	a.NoError(storage.StorePeer(&Peer{
		Name:      "carol",
		PublicKey: att.MarshalPublicKey(),
		FirstSeen: time.Now(),
	}))
	a.NoError(storage.CreateSession("sess-mark", att.MarshalPublicKey()))

	tA := makeToken(0xAA, 32)
	tB := makeToken(0xBB, 32)
	tC := makeToken(0xCC, 32)
	err = storage.SetMeta("sess-mark", NewByteSlicesMeta(ResumptionTokensKey,
		[][]byte{tA, tB, tC}))
	a.NoError(err)

	// Remove B.
	err = storage.RemoveListItem("sess-mark", ResumptionTokensKey, tB)
	a.NoError(err)

	// Pop should return A (first remaining).
	tok, err := storage.PopList("sess-mark", ResumptionTokensKey)
	a.NoError(err)
	a.Equal(tA, tok)

	// Next pop should be C.
	tok, err = storage.PopList("sess-mark", ResumptionTokensKey)
	a.NoError(err)
	a.Equal(tC, tok)
}

func TestRemoveSessionToken_RejectsUnknownToken(t *testing.T) {
	a := require.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	att, err := attest.New()
	a.NoError(err)
	a.NoError(storage.StorePeer(&Peer{
		Name:      "dave",
		PublicKey: att.MarshalPublicKey(),
		FirstSeen: time.Now(),
	}))
	a.NoError(storage.CreateSession("sess-unk", att.MarshalPublicKey()))

	err = storage.SetMeta("sess-unk", NewByteSlicesMeta(ResumptionTokensKey, [][]byte{
		makeToken(0x01, 32),
		makeToken(0x02, 32),
	}))
	a.NoError(err)

	err = storage.RemoveListItem(
		"sess-unk", ResumptionTokensKey, makeToken(0xFF, 32),
	)
	a.ErrorIs(err, ErrNotFound)
}

func TestRemoveSessionToken_RejectsAlreadyRemovedToken(t *testing.T) {
	a := require.New(t)
	storage, cleanup := newTestStorage(t)
	defer cleanup()

	att, err := attest.New()
	a.NoError(err)
	a.NoError(storage.StorePeer(&Peer{
		Name:      "eve",
		PublicKey: att.MarshalPublicKey(),
		FirstSeen: time.Now(),
	}))
	a.NoError(storage.CreateSession("sess-used", att.MarshalPublicKey()))

	tok := makeToken(0x42, 32)
	err = storage.SetMeta("sess-used", NewByteSlicesMeta(ResumptionTokensKey,
		[][]byte{tok}))
	a.NoError(err)

	// First remove succeeds.
	err = storage.RemoveListItem("sess-used", ResumptionTokensKey, tok)
	a.NoError(err)

	// Second remove with same token fails.
	err = storage.RemoveListItem("sess-used", ResumptionTokensKey, tok)
	a.ErrorIs(err, ErrNotFound)
}

// TestSetMetaDoesNotCreateSession checks that clearing the resumption
// tokens of a session, as a transport does when it closes, does not bring
// back a session that was deleted while it was live.
func TestSetMetaDoesNotCreateSession(t *testing.T) {
	cases := []struct {
		name  string
		setup func(a *require.Assertions, s *Storage, id string)
	}{
		{"never stored", func(*require.Assertions, *Storage, string) {}},
		{"deleted", func(a *require.Assertions, s *Storage, id string) {
			tok := makeToken(0x01, 32)
			a.NoError(s.PutSessionResumption(id, nil, [][]byte{tok}, true))
			a.NoError(s.DeleteSession(id))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			store, cleanup := newTestStorage(t)
			defer cleanup()
			tc.setup(a, store, "sess")

			err := store.SetMeta(
				"sess", NewByteSlicesMeta(ResumptionTokensKey, nil),
			)
			a.ErrorIs(err, ErrSessionNotFound)
			// Transports clear the tokens with DeleteMeta, which must
			// leave a missing session alone too.
			err = store.DeleteMeta("sess", ResumptionTokensKey)
			a.ErrorIs(err, engine.ErrMissingNamespace)
			sessions, err := store.ListSessions()
			a.NoError(err)
			a.NotContains(sessions, "sess")
		})
	}
}

func TestSetMetaUpdatesExistingSession(t *testing.T) {
	a := require.New(t)
	store, cleanup := newTestStorage(t)
	defer cleanup()

	tok := makeToken(0x01, 32)
	a.NoError(store.PutSessionResumption("sess", nil, [][]byte{tok}, true))
	a.NoError(store.SetMeta("sess", NewByteSlicesMeta(ResumptionTokensKey, nil)))
	_, err := store.PopList("sess", ResumptionTokensKey)
	a.ErrorIs(err, ErrNotFound)

	relay := makeToken(0x02, 32)
	a.NoError(store.SetMeta(
		"sess", NewByteSlicesMeta(RelayTokensKey, [][]byte{relay}),
	))
	got, err := store.PopList("sess", RelayTokensKey)
	a.NoError(err)
	a.Equal(relay, got)
}

// TestIdleSessionsAreBoundedPerPeer has a peer connect again and again
// without sending anything, and checks that the stored sessions for it
// stay bounded.
func TestIdleSessionsAreBoundedPerPeer(t *testing.T) {
	cases := []struct {
		name string
		opts []StorageOption
		want int
	}{
		{"default", nil, defaultIdleSessionLimit},
		{"custom", []StorageOption{WithIdleSessionLimit(3)}, 3},
		{"disabled", []StorageOption{WithIdleSessionLimit(0)}, 20},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			clk := clock.NewFake(time.Unix(1_700_000_000, 0))
			opts := append([]StorageOption{
				WithDBPath(filepath.Join(t.TempDir(), "db")),
				WithNoPassphrase(),
				WithClock(clk),
			}, tc.opts...)
			s, err := OpenStorage(opts...)
			a.NoError(err)
			defer s.Close()

			att, err := attest.New()
			a.NoError(err)
			pub := att.MarshalPublicKey()
			tok := makeToken(0x01, 32)
			var ids []string
			for i := range 20 {
				id := fmt.Sprintf("s%02d", i)
				ids = append(ids, id)
				a.NoError(s.PutSessionResumption(
					id, pub, [][]byte{tok}, true,
				))
				clk.Advance(time.Second)
			}

			sessions, err := s.ListSessions()
			a.NoError(err)
			a.ElementsMatch(ids[len(ids)-tc.want:], sessions)
		})
	}
}

func TestPruneIdleSessionsKeepsUsedSessions(t *testing.T) {
	a := require.New(t)
	clk := clock.NewFake(time.Unix(1_700_000_000, 0))
	s, err := OpenStorage(
		WithDBPath(filepath.Join(t.TempDir(), "db")),
		WithNoPassphrase(),
		WithClock(clk),
		WithIdleSessionLimit(2),
	)
	a.NoError(err)
	defer s.Close()

	alice, err := attest.New()
	a.NoError(err)
	bob, err := attest.New()
	a.NoError(err)
	alicePK, bobPK := alice.MarshalPublicKey(), bob.MarshalPublicKey()
	a.NoError(s.StorePeer(&Peer{Name: "alice", PublicKey: alicePK}))
	establish := func(id string, pub []byte) {
		a.NoError(s.PutSessionResumption(id, pub, nil, true))
		clk.Advance(time.Second)
	}

	establish("bob-old", bobPK)
	establish("idle-1", alicePK)
	establish("chat", alicePK)
	a.NoError(s.CreateSession("chat", alicePK))
	a.NoError(s.AddChatEntry("chat", []byte("hi"), clk.Now(), SenderPeer))
	establish("named", alicePK)
	a.NoError(s.SetSessionName("named", "keep me"))
	establish("idle-2", alicePK)
	establish("idle-3", alicePK)

	sessions, err := s.ListSessions()
	a.NoError(err)
	a.ElementsMatch(
		[]string{"bob-old", "chat", "named", "idle-2", "idle-3"}, sessions,
	)

	// CreateSession prunes as well.
	a.NoError(s.CreateSession("idle-4", alicePK))
	sessions, err = s.ListSessions()
	a.NoError(err)
	a.ElementsMatch(
		[]string{"bob-old", "chat", "named", "idle-3", "idle-4"}, sessions,
	)
}

func TestPutSessionResumptionDoesNotResetEstablishedAt(t *testing.T) {
	a := require.New(t)
	store, cleanup := newTestStorage(t)
	defer cleanup()

	att, err := attest.New()
	a.NoError(err)
	pub := att.MarshalPublicKey()
	tok := makeToken(0x02, 32)
	a.NoError(store.PutSessionResumption("sess-r", pub, [][]byte{tok}, true))
	first, err := store.GetEstablishedAt("sess-r")
	a.NoError(err)

	time.Sleep(2 * time.Millisecond)
	tok2 := makeToken(0x03, 32)
	a.NoError(store.PutSessionResumption("sess-r", pub, [][]byte{tok2}, true))
	again, err := store.GetEstablishedAt("sess-r")
	a.NoError(err)
	a.True(first.Equal(again))
}

func TestCreateSessionDoesNotResetEstablishedAt(t *testing.T) {
	a := require.New(t)
	store, cleanup := newTestStorage(t)
	defer cleanup()

	att, err := attest.New()
	a.NoError(err)
	a.NoError(store.StorePeer(&Peer{
		Name:      "alice",
		PublicKey: att.MarshalPublicKey(),
		FirstSeen: time.Now(),
	}))
	a.NoError(store.CreateSession("sess-c", att.MarshalPublicKey()))
	first, err := store.GetEstablishedAt("sess-c")
	a.NoError(err)

	time.Sleep(2 * time.Millisecond)
	a.NoError(store.CreateSession("sess-c", att.MarshalPublicKey()))
	again, err := store.GetEstablishedAt("sess-c")
	a.NoError(err)
	a.True(first.Equal(again))
}

func TestFindPeerExpiredDoesNotDeadlock(t *testing.T) {
	a := require.New(t)
	f, err := os.CreateTemp("", "kamune-storage-expired-*.db")
	a.NoError(err)
	a.NoError(f.Close())
	defer func() { _ = os.Remove(f.Name()) }()

	store, err := OpenStorage(
		WithDBPath(f.Name()),
		WithNoPassphrase(),
		WithExpiryDuration(time.Hour),
	)
	a.NoError(err)
	defer func() { _ = store.Close() }()

	att, err := attest.New()
	a.NoError(err)
	a.NoError(store.StorePeer(&Peer{
		Name:      "old",
		PublicKey: att.MarshalPublicKey(),
		FirstSeen: time.Now().Add(-48 * time.Hour),
	}))

	_, err = store.FindPeer(att.MarshalPublicKey())
	a.ErrorIs(err, ErrPeerExpired)
	_, err = store.FindPeer(att.MarshalPublicKey())
	a.Error(err)
	a.False(errors.Is(err, ErrPeerExpired))
}

func TestRemoveListItemUnequalLength(t *testing.T) {
	a := require.New(t)
	store, cleanup := newTestStorage(t)
	defer cleanup()

	att, err := attest.New()
	a.NoError(err)
	a.NoError(store.StorePeer(&Peer{
		Name:      "len",
		PublicKey: att.MarshalPublicKey(),
		FirstSeen: time.Now(),
	}))
	a.NoError(store.CreateSession("sess-len", att.MarshalPublicKey()))
	tok := makeToken(0xAB, 32)
	a.NoError(store.SetMeta(
		"sess-len", NewByteSlicesMeta(ResumptionTokensKey, [][]byte{tok}),
	))

	err = store.RemoveListItem("sess-len", ResumptionTokensKey, []byte{1})
	a.ErrorIs(err, ErrNotFound)
	got, err := store.PopList("sess-len", ResumptionTokensKey)
	a.NoError(err)
	a.Equal(tok, got)
}

func openWithPass(path string, pass []byte) (*Storage, error) {
	return OpenStorage(
		WithDBPath(path),
		WithCreateDB(false),
		WithPassphraseHandler(func() ([]byte, error) { return pass, nil }),
	)
}

func TestChangePassphrase(t *testing.T) {
	cases := []struct {
		name     string
		old, new []byte
	}{
		{"set on passwordless database", []byte(""), []byte("secret")},
		{"replace", []byte("old-secret"), []byte("new-secret")},
		{"remove", []byte("old-secret"), []byte("")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			path := filepath.Join(t.TempDir(), "db")

			s, err := OpenStorage(
				WithDBPath(path),
				WithPassphraseHandler(func() ([]byte, error) {
					return tc.old, nil
				}),
			)
			a.NoError(err)
			at, err := s.Attester()
			a.NoError(err)
			peer, err := attest.New()
			a.NoError(err)
			a.NoError(s.StorePeer(&Peer{
				Name: "alice", PublicKey: peer.MarshalPublicKey(),
			}))
			a.NoError(s.CreateSession("sess", peer.MarshalPublicKey()))
			a.NoError(s.AddChatEntry(
				"sess", []byte("hello"), time.Now(), SenderLocal,
			))
			a.NoError(s.SetSettings("app", "k", "v"))

			a.NoError(s.ChangePassphrase(tc.old, tc.new))

			// The open handle keeps working under the new key.
			v, err := s.GetSettings("app", "k")
			a.NoError(err)
			a.Equal("v", v)
			a.NoError(s.Close())

			_, err = openWithPass(path, tc.old)
			a.ErrorIs(err, ErrWrongPassphrase)

			s, err = openWithPass(path, tc.new)
			a.NoError(err)
			defer s.Close()
			reloaded, err := s.Attester()
			a.NoError(err)
			a.Equal(at.MarshalPublicKey(), reloaded.MarshalPublicKey())
			entries, err := s.GetChatHistory("sess")
			a.NoError(err)
			a.Len(entries, 1)
			a.Equal([]byte("hello"), entries[0].Data)
		})
	}
}

func TestChangePassphrase_WrongOldPassphrase(t *testing.T) {
	a := require.New(t)
	path := filepath.Join(t.TempDir(), "db")
	pass := []byte("right")

	s, err := OpenStorage(
		WithDBPath(path),
		WithPassphraseHandler(func() ([]byte, error) { return pass, nil }),
	)
	a.NoError(err)
	a.NoError(s.SetSettings("app", "k", "v"))

	err = s.ChangePassphrase([]byte("wrong"), []byte("new"))
	a.ErrorIs(err, ErrWrongPassphrase)
	v, err := s.GetSettings("app", "k")
	a.NoError(err)
	a.Equal("v", v)
	a.NoError(s.Close())

	s, err = openWithPass(path, pass)
	a.NoError(err)
	a.NoError(s.Close())
}

func TestOpenStorage_DirectoryPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits do not control access on Windows")
	}
	cases := []struct {
		// setup prepares the home directory and returns the database path
		// to pass with WithDBPath, or "" for the default path.
		setup func(t *testing.T, home string) string
		want  map[string]os.FileMode // relative to home
		name  string
	}{
		{
			name: "created directories are private",
			setup: func(t *testing.T, home string) string {
				return filepath.Join(home, "a", "b", "db")
			},
			want: map[string]os.FileMode{"a": 0o700, "a/b": 0o700},
		},
		{
			name: "default directory is tightened",
			setup: func(t *testing.T, home string) string {
				dir := filepath.Join(home, ".config", "kamune")
				require.New(t).NoError(os.MkdirAll(dir, 0o740))
				require.New(t).NoError(os.Chmod(dir, 0o740))
				return ""
			},
			want: map[string]os.FileMode{".config/kamune": 0o700},
		},
		{
			name: "chosen existing directory is left alone",
			setup: func(t *testing.T, home string) string {
				dir := filepath.Join(home, "shared")
				require.New(t).NoError(os.Mkdir(dir, 0o750))
				require.New(t).NoError(os.Chmod(dir, 0o750))
				return filepath.Join(dir, "db")
			},
			want: map[string]os.FileMode{"shared": 0o750},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("KAMUNE_DB_PATH", "")

			opts := []StorageOption{WithNoPassphrase()}
			if path := tc.setup(t, home); path != "" {
				opts = append(opts, WithDBPath(path))
			}
			s, err := OpenStorage(opts...)
			a.NoError(err)
			a.NoError(s.Close())

			for rel, want := range tc.want {
				info, err := os.Stat(filepath.Join(home, rel))
				a.NoError(err)
				a.Equal(want, info.Mode().Perm(), rel)
			}
		})
	}
}

func TestPaddedSize(t *testing.T) {
	cases := []struct{ n, want int }{
		{0, 512},
		{512, 512},
		{513, 1024},
		{4096, 4096},
		{4097, 16 << 10},
		{64 << 10, 64 << 10},
		{64<<10 + 1, 128 << 10},
		{200 << 10, 256 << 10},
	}
	for _, tc := range cases {
		require.New(t).Equal(tc.want, paddedSize(tc.n), "n=%d", tc.n)
	}
}
