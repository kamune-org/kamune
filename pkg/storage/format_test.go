package storage

import (
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
