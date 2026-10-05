package storage

import (
	"bytes"
	"crypto/rand"
	"crypto/sha3"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/internal/engine"
	"github.com/kamune-org/kamune/internal/enigma"
	"github.com/kamune-org/kamune/pkg/attest"
)

// The labels the engine of v0.6.0 derived its keys with.
const (
	v060PassLabel = "derived-passphrase-key"
	v060KEKLabel  = "key-encryption-key"
	v060DEKLabel  = "data-encryption-key"
)

// writeV060Database writes a database at path as v0.6.0 did: its data key
// wrapped under a single HKDF of pass, every value sealed without
// associated data, the peer pub under the SHA3-512 of its public key, a
// session under its ID with one chat entry under its receive time and
// sender, and a setting under its plain name.
func writeV060Database(
	t *testing.T, path string, pass, pub []byte, sessionID string,
) {
	t.Helper()
	a := require.New(t)
	random := func(n int) []byte {
		b := make([]byte, n)
		_, _ = rand.Read(b)
		return b
	}
	secret, secretSalt := random(32), random(32)
	deriveSalt, wrappedSalt := random(32), random(32)
	data, err := enigma.NewEnigma(secret, secretSalt, []byte(v060DEKLabel))
	a.NoError(err)
	derived, err := enigma.Derive(
		pass, deriveSalt, []byte(v060PassLabel), 32,
	)
	a.NoError(err)
	kek, err := enigma.NewEnigma(derived, wrappedSalt, []byte(v060KEKLabel))
	a.NoError(err)
	peer, err := proto.Marshal(&pb.Peer{
		Name:      "alice",
		PublicKey: pub,
		FirstSeen: timestamppb.Now(),
		LastSeen:  timestamppb.Now(),
	})
	a.NoError(err)
	peerKey := sha3.Sum512(pub)

	db, err := bolt.Open(path, 0600, nil)
	a.NoError(err)
	defer db.Close()
	a.NoError(db.Update(func(tx *bolt.Tx) error {
		bucket := func(names ...string) *bolt.Bucket {
			b, err := tx.CreateBucketIfNotExists([]byte(names[0]))
			a.NoError(err)
			for _, name := range names[1:] {
				b, err = b.CreateBucketIfNotExists([]byte(name))
				a.NoError(err)
			}
			return b
		}
		put := func(b *bolt.Bucket, key, value []byte) {
			a.NoError(b.Put(key, value))
		}
		def := bucket(engine.DefaultNamespace)
		put(def, []byte("secret-salt"), secretSalt)
		put(def, []byte("derive-salt"), deriveSalt)
		put(def, []byte("wrapped-salt"), wrappedSalt)
		put(def, []byte("wrapped-key"), kek.Encrypt(secret))
		put(bucket(engine.PeersNamespace), peerKey[:], data.Encrypt(peer))
		put(
			bucket(engine.SettingsNamespace),
			[]byte("bus:theme"), data.Encrypt([]byte("dark")),
		)
		meta := bucket(engine.SessionsNamespace, sessionID, "meta")
		put(meta, []byte(PeerKey), data.Encrypt(pub))
		put(meta, sessionMetaKey, data.Encrypt([]byte("work")))
		put(
			bucket(engine.SessionsNamespace, sessionID, "chat"),
			chatKey(time.Unix(1_790_000_000, 0), SenderPeer, 7),
			data.Encrypt([]byte("hello")),
		)
		return nil
	}))
}

// dumpBolt returns every key and value in the bolt file at path, by the
// path of buckets that holds it.
func dumpBolt(t *testing.T, path string) map[string]string {
	t.Helper()
	a := require.New(t)
	db, err := bolt.Open(path, 0600, &bolt.Options{ReadOnly: true})
	a.NoError(err)
	defer db.Close()
	out := map[string]string{}
	var walk func(prefix string, b *bolt.Bucket) error
	walk = func(prefix string, b *bolt.Bucket) error {
		return b.ForEach(func(k, v []byte) error {
			name := fmt.Sprintf("%s/%x", prefix, k)
			if v == nil {
				out[name] = "bucket"
				return walk(name, b.Bucket(k))
			}
			out[name] = fmt.Sprintf("%x", v)
			return nil
		})
	}
	a.NoError(db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			return walk(fmt.Sprintf("%x", name), b)
		})
	}))
	return out
}

// TestOpenStorageLeavesOlderDatabaseWhenUpgradeFails opens a database
// written by v0.6.0 while its key wrapping cannot be upgraded, as the
// lock file cannot be created, and checks that the open fails and leaves
// every key and value as v0.6.0 wrote them, so that v0.6.0 can still
// read the database. An open that can upgrade it then finds everything.
func TestOpenStorageLeavesOlderDatabaseWhenUpgradeFails(t *testing.T) {
	a := require.New(t)
	path := filepath.Join(t.TempDir(), "db")
	pass := []byte("correct horse")
	open := func() (*Storage, error) {
		return OpenStorage(
			WithDBPath(path),
			WithPassphraseHandler(func() ([]byte, error) {
				return pass, nil
			}),
		)
	}
	att, err := attest.New()
	a.NoError(err)
	pub := att.MarshalPublicKey()
	const sessionID = "QWERTYUIOPASDFGHJKLZXCVB"
	writeV060Database(t, path, pass, pub, sessionID)
	before := dumpBolt(t, path)

	// A directory where the lock file belongs cannot be opened as a file.
	a.NoError(os.Mkdir(path+".lock", 0700))
	s, err := open()
	a.ErrorIs(err, ErrUpgradeFailed)
	a.Nil(s)
	a.Equal(before, dumpBolt(t, path), "older database changed")

	a.NoError(os.Remove(path + ".lock"))
	s, err = open()
	a.NoError(err)
	defer s.Close()
	version, err := s.formatVersion()
	a.NoError(err)
	a.Equal(byte(storageFormat), version)
	p, err := s.FindPeer(pub)
	a.NoError(err)
	a.Equal("alice", p.Name)
	sessions, err := s.ListSessions()
	a.NoError(err)
	a.Equal([]string{sessionID}, sessions)
	name, err := s.GetSessionName(sessionID)
	a.NoError(err)
	a.Equal("work", name)
	history, err := s.GetChatHistory(sessionID)
	a.NoError(err)
	a.Len(history, 1)
	a.Equal([]byte("hello"), history[0].Data)
	theme, err := s.GetSettings("bus", "theme")
	a.NoError(err)
	a.Equal("dark", theme)
}

// upgradeErrStore is a [Store] whose key upgrade failed with err.
type upgradeErrStore struct {
	engine.Store
	err error
}

func (s upgradeErrStore) UpgradeErr() error { return s.err }

// TestOpenStorageChecksBackendUpgrade checks that a backend that reports a
// failed upgrade is not converted while its layout is older, and is used
// as it is once its layout is current.
func TestOpenStorageChecksBackendUpgrade(t *testing.T) {
	a := require.New(t)
	path := filepath.Join(t.TempDir(), "db")
	db, err := engine.NewBoltDB(path, nil)
	a.NoError(err)
	defer db.Close()
	failed := errors.New("disk full")

	_, err = OpenStorage(WithBackend(upgradeErrStore{db, failed}))
	a.ErrorIs(err, ErrUpgradeFailed)
	a.ErrorIs(err, failed)
	a.NoError(db.Query(func(b Namespace) error {
		_, err := b.Sub([]byte(engine.DefaultNamespace)).
			GetEncrypted([]byte(nameKeyKey))
		a.ErrorIs(err, engine.ErrMissingItem, "name key written")
		return nil
	}))

	s, err := OpenStorage(WithBackend(db))
	a.NoError(err)
	a.NoError(s.SetSettings("bus", "theme", "dark"))
	s, err = OpenStorage(WithBackend(upgradeErrStore{db, failed}))
	a.NoError(err, "a current layout needs no key upgrade")
	theme, err := s.GetSettings("bus", "theme")
	a.NoError(err)
	a.Equal("dark", theme)
}

// compactPending reports whether s has an upgrade that was not compacted.
func compactPending(t *testing.T, s *Storage) bool {
	t.Helper()
	var pending bool
	require.New(t).NoError(s.engine.Query(func(b Namespace) error {
		_, err := b.Sub([]byte(engine.DefaultNamespace)).
			GetEncrypted([]byte(compactPendingKey))
		pending = err == nil
		return nil
	}))
	return pending
}

// TestOpenStorageRetriesCompactionAfterUpgrade upgrades a database while
// it cannot be compacted, as its lock file cannot be created, and checks
// that the next open compacts it, so that its old names leave the file.
func TestOpenStorageRetriesCompactionAfterUpgrade(t *testing.T) {
	a := require.New(t)
	path := filepath.Join(t.TempDir(), "db")
	open := func() *Storage {
		s, err := OpenStorage(WithDBPath(path), WithNoPassphrase())
		a.NoError(err)
		return s
	}
	keys := map[string][]byte{}
	for _, name := range []string{"alice", "mallory"} {
		att, err := attest.New()
		a.NoError(err)
		keys[name] = att.MarshalPublicKey()
	}
	const sessionID = "QWERTYUIOPASDFGHJKLZXCVB"
	s := open()
	writeLegacyLayout(
		t, s, sessionID, map[string][]byte{"alice": keys["alice"]},
		keys["alice"], keys["mallory"], [][]byte{makeToken(1, 32)},
	)
	a.NoError(s.Close())

	// A directory where the lock file belongs cannot be opened as a file.
	a.NoError(os.Remove(path + ".lock"))
	a.NoError(os.Mkdir(path+".lock", 0700))
	s = open()
	version, err := s.formatVersion()
	a.NoError(err)
	a.Equal(byte(storageFormat), version)
	a.True(compactPending(t, s), "compaction not left pending")
	a.NoError(s.Close())

	a.NoError(os.Remove(path + ".lock"))
	s = open()
	a.False(compactPending(t, s), "compaction still pending")
	sessions, err := s.ListSessions()
	a.NoError(err)
	a.Equal([]string{sessionID}, sessions)
	a.NoError(s.Close())

	raw, err := os.ReadFile(path)
	a.NoError(err)
	a.False(bytes.Contains(raw, []byte(sessionID)), "session ID in file")
	a.False(
		bytes.Contains(raw, []byte("daemon:incognito")),
		"setting name in file",
	)
}

// TestOpenStorageCompactsAfterFailedDelete deletes a session and a peer
// while the database cannot be compacted, as its lock file cannot be
// created, and checks that both deletes report ErrCompactFailed and that
// the next open compacts the deleted data out of the file.
func TestOpenStorageCompactsAfterFailedDelete(t *testing.T) {
	a := require.New(t)
	path := filepath.Join(t.TempDir(), "db")
	open := func() *Storage {
		s, err := OpenStorage(WithDBPath(path), WithNoPassphrase())
		a.NoError(err)
		return s
	}
	const sessionID = "QKZDELETEDSESSIONID23456"
	att, err := attest.New()
	a.NoError(err)
	pub := att.MarshalPublicKey()

	s := open()
	a.NoError(s.StorePeer(&Peer{Name: "deleted", PublicKey: pub}))
	a.NoError(s.CreateSession(sessionID, pub))
	for i := range 20 {
		a.NoError(s.AddChatEntry(
			sessionID, fmt.Appendf(nil, "message %d", i), time.Now(),
			SenderPeer,
		))
	}
	a.False(compactPending(t, s))
	a.NoError(s.Close())
	before := rawValues(t, path)

	// A directory where the lock file belongs cannot be opened as a file.
	a.NoError(os.Remove(path + ".lock"))
	a.NoError(os.Mkdir(path+".lock", 0700))
	s = open()
	a.ErrorIs(s.DeleteSession(sessionID), ErrCompactFailed)
	a.ErrorIs(s.DeletePeer(pub), ErrCompactFailed)
	a.True(compactPending(t, s), "compaction not left pending")
	a.NoError(s.Close())

	a.NoError(os.Remove(path + ".lock"))
	s = open()
	a.False(compactPending(t, s), "compaction still pending")
	sessions, err := s.ListSessions()
	a.NoError(err)
	a.Empty(sessions)
	a.NoError(s.Close())

	after := rawValues(t, path)
	raw, err := os.ReadFile(path)
	a.NoError(err)
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
	a.GreaterOrEqual(deleted, 20, "the deleted history and peer")
}

// TestCompactKeepsNewerMark checks that a compaction clears only the mark
// it saw before it started: a mark that a later delete wrote stays, so
// that the data freed by that delete is compacted later.
func TestCompactKeepsNewerMark(t *testing.T) {
	a := require.New(t)
	s, err := OpenStorage(
		WithDBPath(filepath.Join(t.TempDir(), "db")), WithNoPassphrase(),
	)
	a.NoError(err)
	defer s.Close()

	mark := func() []byte {
		a.NoError(s.engine.Command(markCompactPending))
		v, pending, err := s.compactMark()
		a.NoError(err)
		a.True(pending)
		return v
	}
	seen := mark()
	mark()
	s.clearCompactMark(seen)
	a.True(compactPending(t, s), "a newer mark was cleared")

	a.NoError(s.Compact())
	a.False(compactPending(t, s), "compaction still pending")
}
