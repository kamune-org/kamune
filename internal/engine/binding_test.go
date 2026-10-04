package engine

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
)

// rawBucket returns the bucket at path in tx.
func rawBucket(tx *bolt.Tx, path ...string) *bolt.Bucket {
	b := tx.Bucket([]byte(path[0]))
	for _, name := range path[1:] {
		b = b.Bucket([]byte(name))
	}
	return b
}

// copyRaw copies the stored bytes of key in the bucket at from to dstKey in
// the bucket at to, as someone without the data key could.
func copyRaw(
	t *testing.T, path string, from []string, key string,
	to []string, dstKey string,
) {
	t.Helper()
	a := require.New(t)
	db, err := bolt.Open(path, 0600, nil)
	a.NoError(err)
	defer db.Close()
	a.NoError(db.Update(func(tx *bolt.Tx) error {
		v := bytes.Clone(rawBucket(tx, from...).Get([]byte(key)))
		a.NotNil(v)
		return rawBucket(tx, to...).Put([]byte(dstKey), v)
	}))
}

// rawValue returns the stored bytes of key in the bucket at bucket.
func rawValue(t *testing.T, path string, key string, bucket ...string) []byte {
	t.Helper()
	a := require.New(t)
	db, err := bolt.Open(path, 0600, nil)
	a.NoError(err)
	defer db.Close()
	var v []byte
	a.NoError(db.View(func(tx *bolt.Tx) error {
		v = bytes.Clone(rawBucket(tx, bucket...).Get([]byte(key)))
		return nil
	}))
	return v
}

func TestValueBinding_RejectsRelocatedValue(t *testing.T) {
	cases := []struct {
		name string
		to   []string
		key  string
	}{
		{"other key", []string{PeersNamespace}, "mallory"},
		{"other bucket", []string{SettingsNamespace}, "alice"},
		{"nested bucket", []string{SessionsNamespace, "s", "meta"}, "alice"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			path := filepath.Join(t.TempDir(), "db")
			pass := []byte("pass")

			db, err := NewBoltDB(path, pass)
			a.NoError(err)
			a.NoError(db.Command(func(b Namespace) error {
				err := b.Sub([]byte(PeersNamespace)).PutEncrypted(
					[]byte("alice"), []byte("alice-record"),
				)
				if err != nil {
					return err
				}
				b.Ensure([]byte(SessionsNamespace)).
					Ensure([]byte("s")).
					Ensure([]byte("meta"))
				return nil
			}))
			a.NoError(db.Close())

			copyRaw(t, path, []string{PeersNamespace}, "alice", tc.to, tc.key)

			db, err = NewBoltDB(path, pass)
			a.NoError(err)
			defer db.Close()
			a.NoError(db.Query(func(b Namespace) error {
				ns := b
				for _, name := range tc.to {
					ns = ns.Sub([]byte(name))
				}
				_, err := ns.GetEncrypted([]byte(tc.key))
				a.Error(err, "relocated value must not open")
				for k := range ns.IterateEncrypted() {
					a.NotEqual(tc.key, string(k))
				}

				v, err := b.Sub([]byte(PeersNamespace)).
					GetEncrypted([]byte("alice"))
				a.NoError(err)
				a.Equal([]byte("alice-record"), v)
				return nil
			}))
		})
	}
}

// putRaw stores v at key in the bucket at bucket, creating the buckets that
// are missing, as someone without the data key could.
func putRaw(
	t *testing.T, path string, bucket []string, key string, v []byte,
) {
	t.Helper()
	a := require.New(t)
	db, err := bolt.Open(path, 0600, nil)
	a.NoError(err)
	defer db.Close()
	a.NoError(db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(bucket[0]))
		for _, name := range bucket[1:] {
			if err != nil {
				return err
			}
			b, err = b.CreateBucketIfNotExists([]byte(name))
		}
		if err != nil {
			return err
		}
		return b.Put([]byte(key), v)
	}))
}

// markerBound reports whether the binding marker of db opens under its
// data key.
func markerBound(t *testing.T, db *BoltStore) bool {
	t.Helper()
	var bound bool
	require.New(t).NoError(db.db.View(func(tx *bolt.Tx) error {
		bound = isBound(tx, db.cipher)
		return nil
	}))
	return bound
}

func TestNewBoltDB_BindsLegacyValues(t *testing.T) {
	a := require.New(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "db")
	pass := []byte("pass")
	// writeStore seals the peer value without associated data, as stores
	// written before values were bound to their location did.
	writeStore(t, path, pass, defaultKDF)
	legacy := rawValue(t, path, "peer", PeersNamespace)
	before := readMeta(t, path)
	a.Nil(rawValue(t, path, bindingKey, DefaultNamespace))

	db, err := NewBoltDB(path, pass)
	a.NoError(err)
	a.True(db.bound)
	a.True(markerBound(t, db))
	requirePeerData(t, db)
	a.NoError(db.Close())

	after := readMeta(t, path)
	a.NotEqual(before.secretSalt, after.secretSalt, "data key not replaced")
	raw := readFile(t, path)
	a.False(bytes.Contains(raw, legacy), "legacy ciphertext")
	a.False(bytes.Contains(raw, before.wrap.wrappedKey), "old wrapped key")
	requireOnlyDB(t, dir)

	// The value is now bound: a copy under another key does not open, and
	// the store is not bound again.
	copyRaw(
		t, path, []string{PeersNamespace}, "peer",
		[]string{PeersNamespace}, "copy",
	)
	db, err = NewBoltDB(path, pass)
	a.NoError(err)
	requirePeerData(t, db)
	a.NoError(db.Query(func(b Namespace) error {
		_, err := b.Sub([]byte(PeersNamespace)).GetEncrypted([]byte("copy"))
		a.Error(err)
		return nil
	}))
	a.NoError(db.Close())
	a.Equal(after, readMeta(t, path), "no second upgrade")
}

// TestValueBinding_RejectsLegacyValueInBoundStore puts a value from a copy
// of the store taken before it was bound, which has no associated data,
// into the bound store: at the key it came from, at another key and in
// other buckets. It must open nowhere, also when the binding marker is
// removed or replaced, which makes the next open bind the store again.
func TestValueBinding_RejectsLegacyValueInBoundStore(t *testing.T) {
	pass := []byte("pass")
	src := filepath.Join(t.TempDir(), "db")
	writeStore(t, src, pass, defaultKDF)
	legacy := rawValue(t, src, "peer", PeersNamespace)
	db, err := NewBoltDB(src, pass)
	require.New(t).NoError(err)
	require.New(t).NoError(db.Command(func(b Namespace) error {
		return b.Sub([]byte(PeersNamespace)).PutEncrypted(
			[]byte("bob"), []byte("bob-data"),
		)
	}))
	require.New(t).NoError(db.Close())
	bound := readFile(t, src)

	targets := []struct {
		bucket []string
		key    string
	}{
		{[]string{PeersNamespace}, "peer"},
		{[]string{PeersNamespace}, "mallory"},
		{[]string{SettingsNamespace}, "verification_mode"},
		{[]string{SessionsNamespace, "s", "meta"}, "peer"},
	}
	deleteMarker := func(t *testing.T, path string) {
		deleteRaw(t, path, bindingKey)
	}
	cases := []struct {
		marker func(t *testing.T, path string)
		name   string
		noLock bool
	}{
		{name: "marker kept", marker: func(*testing.T, string) {}},
		{name: "marker deleted", marker: deleteMarker},
		{
			name:   "marker deleted without lock file",
			marker: deleteMarker,
			noLock: true,
		},
		{
			name: "plaintext marker",
			marker: func(t *testing.T, path string) {
				putRaw(
					t, path, []string{DefaultNamespace}, bindingKey,
					[]byte{valueADVersion},
				)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			path := filepath.Join(t.TempDir(), "db")
			a.NoError(os.WriteFile(path, bound, 0600))
			for _, tg := range targets {
				putRaw(t, path, tg.bucket, tg.key, legacy)
			}
			tc.marker(t, path)
			if tc.noLock {
				a.NoError(os.Mkdir(lockPath(path), 0700))
			}

			// The first open may bind the store again; the second
			// reads what it left.
			for range 2 {
				db, err := NewBoltDB(path, pass)
				a.NoError(err)
				a.NoError(db.Query(func(b Namespace) error {
					for _, tg := range targets {
						ns := b
						for _, name := range tg.bucket {
							ns = ns.Sub([]byte(name))
						}
						_, err := ns.GetEncrypted([]byte(tg.key))
						a.Error(err, "%v/%s opened", tg.bucket, tg.key)
						for k := range ns.IterateEncrypted() {
							a.NotEqual(tg.key, string(k))
						}
					}
					v, err := b.Sub([]byte(PeersNamespace)).
						GetEncrypted([]byte("bob"))
					a.NoError(err)
					a.Equal([]byte("bob-data"), v)
					return nil
				}))
				a.NoError(db.Close())
			}
		})
	}
}

// TestValueBinding_UnboundValuesOpenOnlyBeforeBinding seals a value under
// the data key in use without associated data, which only a store written
// before values were bound holds. A bound store must not open it.
func TestValueBinding_UnboundValuesOpenOnlyBeforeBinding(t *testing.T) {
	cases := []struct {
		name   string
		noLock bool
	}{
		{"bound store", false},
		{"store opened without its lock file", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			path := filepath.Join(t.TempDir(), "db")
			writeStore(t, path, []byte("pass"), defaultKDF)
			if tc.noLock {
				// The store cannot be rewritten, so it stays unbound.
				a.NoError(os.Mkdir(lockPath(path), 0700))
			}
			db, err := NewBoltDB(path, []byte("pass"))
			a.NoError(err)
			defer db.Close()
			a.Equal(!tc.noLock, db.bound)

			a.NoError(db.db.Update(func(tx *bolt.Tx) error {
				return tx.Bucket(peersNamespace).Put(
					[]byte("unbound"), db.cipher.Encrypt([]byte("data")),
				)
			}))
			a.NoError(db.Query(func(b Namespace) error {
				peers := b.Sub([]byte(PeersNamespace))
				_, err := peers.GetEncrypted([]byte("unbound"))
				var keys []string
				for k := range peers.IterateEncrypted() {
					keys = append(keys, string(k))
				}
				if tc.noLock {
					a.NoError(err)
					a.Contains(keys, "unbound")
				} else {
					a.Error(err)
					a.NotContains(keys, "unbound")
				}
				return nil
			}))
		})
	}
}

func TestOpenValue(t *testing.T) {
	c, err := newDataCipher(randomBytes(secretSize), randomBytes(saltSize))
	require.New(t).NoError(err)
	path := [][]byte{[]byte("bucket")}
	key := []byte("key")
	cases := []struct {
		name   string
		sealed []byte
		legacy bool
		ok     bool
	}{
		{"bound", sealValue(c, path, key, []byte("v")), false, true},
		{
			"bound with legacy",
			sealValue(c, path, key, []byte("v")), true, true,
		},
		{"no associated data", c.Encrypt([]byte("v")), false, false},
		{"no associated data with legacy", c.Encrypt([]byte("v")), true, true},
		{
			"other location with legacy",
			sealValue(c, path, []byte("other"), []byte("v")), true, false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			v, err := openValue(c, path, key, tc.sealed, tc.legacy)
			if !tc.ok {
				a.Error(err)
				return
			}
			a.NoError(err)
			a.Equal([]byte("v"), v)
		})
	}
}

func TestNewBoltDB_ReadsLegacyValuesWithoutLockFile(t *testing.T) {
	a := require.New(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "db")
	pass := []byte("pass")
	writeStore(t, path, pass, defaultKDF)
	// Without its lock file the store cannot be rewritten, so its values
	// stay unbound but must still be readable.
	a.NoError(os.Mkdir(lockPath(path), 0700))

	db, err := NewBoltDB(path, pass)
	a.NoError(err)
	defer db.Close()
	a.False(db.bound)
	requirePeerData(t, db)
	a.NoError(db.Command(func(b Namespace) error {
		return b.Sub([]byte(PeersNamespace)).PutEncrypted(
			[]byte("new"), []byte("bound"),
		)
	}))
	a.NoError(db.Query(func(b Namespace) error {
		got := map[string]string{}
		for k, v := range b.Sub([]byte(PeersNamespace)).IterateEncrypted() {
			got[string(k)] = string(v)
		}
		a.Equal(map[string]string{"peer": "peer-data", "new": "bound"}, got)
		return nil
	}))
}

func TestRotateDataKey_BindsValues(t *testing.T) {
	cases := []struct {
		name  string
		bound bool
	}{
		{"bound store", true},
		// A store stays unbound when its binding upgrade at open fails.
		{"unbound store", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			path := filepath.Join(t.TempDir(), "db")
			db, err := NewBoltDB(path, []byte("old"))
			a.NoError(err)
			a.NoError(db.Command(func(b Namespace) error {
				return b.Sub([]byte(PeersNamespace)).PutEncrypted(
					[]byte("peer"), []byte("peer-data"),
				)
			}))
			a.NoError(db.db.Update(func(tx *bolt.Tx) error {
				return tx.Bucket(peersNamespace).Put(
					[]byte("unbound"), db.cipher.Encrypt([]byte("data")),
				)
			}))
			db.bound = tc.bound

			a.NoError(db.RotateDataKey([]byte("old"), []byte("new")))
			a.True(db.bound)
			a.True(markerBound(t, db))
			requirePeerData(t, db)
			a.NoError(db.Query(func(b Namespace) error {
				v, err := b.Sub([]byte(PeersNamespace)).
					GetEncrypted([]byte("unbound"))
				if tc.bound {
					a.Error(err, "unbound value re-encrypted")
					return nil
				}
				a.NoError(err)
				a.Equal([]byte("data"), v)
				return nil
			}))
			a.NoError(db.Close())
			rotated := readMeta(t, path)

			copyRaw(
				t, path, []string{PeersNamespace}, "peer",
				[]string{PeersNamespace}, "copy",
			)
			db, err = NewBoltDB(path, []byte("new"))
			a.NoError(err)
			requirePeerData(t, db)
			a.NoError(db.Query(func(b Namespace) error {
				_, err := b.Sub([]byte(PeersNamespace)).
					GetEncrypted([]byte("copy"))
				a.Error(err)
				return nil
			}))
			a.NoError(db.Close())
			a.Equal(rotated, readMeta(t, path), "bound again at open")
		})
	}
}

func TestValueAD_IsUnambiguous(t *testing.T) {
	cases := []struct {
		name         string
		path1, path2 [][]byte
		key1, key2   string
	}{
		{
			"name boundary",
			[][]byte{[]byte("ab"), []byte("c")},
			[][]byte{[]byte("a"), []byte("bc")}, "k", "k",
		},
		{
			"path and key boundary",
			[][]byte{[]byte("a"), []byte("b")},
			[][]byte{[]byte("a")}, "k", "bk",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			a.NotEqual(
				valueAD(tc.path1, []byte(tc.key1)),
				valueAD(tc.path2, []byte(tc.key2)),
			)
		})
	}
}
