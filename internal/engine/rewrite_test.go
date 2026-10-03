package engine

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
)

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.New(t).NoError(err)
	return data
}

// requireOnlyDB checks that dir holds only the database and its lock file.
func requireOnlyDB(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	a := require.New(t)
	a.NoError(err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	a.Equal(
		[]string{"db", "db.lock"}, names,
		"temporary copies must not be left behind",
	)
}

func TestRotation_LeavesNoStaleKeyMaterial(t *testing.T) {
	cases := []struct {
		name    string
		rotate  func(s *BoltStore, old, new []byte) error
		dataKey bool
	}{
		{"passphrase", (*BoltStore).RotatePassphrase, false},
		{"data key", (*BoltStore).RotateDataKey, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			dir := t.TempDir()
			path := filepath.Join(dir, "db")

			db, err := NewBoltDB(path, []byte("old"))
			a.NoError(err)
			a.NoError(db.Command(func(b Namespace) error {
				return b.Sub([]byte(PeersNamespace)).PutEncrypted(
					[]byte("peer"), []byte("peer-data"),
				)
			}))
			var oldValue []byte
			a.NoError(db.db.View(func(tx *bolt.Tx) error {
				oldValue = bytes.Clone(
					tx.Bucket(peersNamespace).Get([]byte("peer")),
				)
				return nil
			}))
			a.NoError(db.Close())
			before := readMeta(t, path)

			db, err = NewBoltDB(path, []byte("old"))
			a.NoError(err)
			a.NoError(tc.rotate(db, []byte("old"), []byte("new")))
			requirePeerData(t, db)
			a.NoError(db.Close())

			raw := readFile(t, path)
			for name, stale := range map[string][]byte{
				"wrapped key":  before.wrap.wrappedKey,
				"derive salt":  before.wrap.deriveSalt,
				"wrapped salt": before.wrap.wrappedSalt,
			} {
				a.False(bytes.Contains(raw, stale), "old %s in file", name)
			}
			if tc.dataKey {
				a.False(bytes.Contains(raw, before.secretSalt))
				a.False(bytes.Contains(raw, oldValue), "old ciphertext")
			}
			requireOnlyDB(t, dir)

			db, err = NewBoltDB(path, []byte("new"))
			a.NoError(err)
			requirePeerData(t, db)
			a.NoError(db.Close())
		})
	}
}

func TestNewBoltDB_UpgradeLeavesNoLegacyKey(t *testing.T) {
	a := require.New(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "db")
	pass := []byte("legacy-pass")
	writeStore(t, path, pass, legacyKDF)
	legacy := readMeta(t, path)

	db, err := NewBoltDB(path, pass)
	a.NoError(err)
	requirePeerData(t, db)
	a.NoError(db.Close())

	raw := readFile(t, path)
	a.False(bytes.Contains(raw, legacy.wrap.wrappedKey))
	a.False(bytes.Contains(raw, legacy.wrap.deriveSalt))
	a.False(bytes.Contains(raw, legacy.wrap.wrappedSalt))
	requireOnlyDB(t, dir)
}

func TestRotation_FailureLeavesStoreUnchanged(t *testing.T) {
	a := require.New(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "db")

	db, err := NewBoltDB(path, []byte("pass"))
	a.NoError(err)
	defer db.Close()
	a.NoError(db.Command(func(b Namespace) error {
		return b.Sub([]byte(PeersNamespace)).PutEncrypted(
			[]byte("peer"), []byte("peer-data"),
		)
	}))
	before := readFile(t, path)

	a.Error(db.RotatePassphrase([]byte("wrong"), []byte("new")))
	a.Error(db.RotateDataKey([]byte("wrong"), []byte("new")))

	a.Equal(before, readFile(t, path))
	requireOnlyDB(t, dir)
	requirePeerData(t, db)
	a.NoError(db.Command(func(b Namespace) error {
		return b.Sub([]byte(PeersNamespace)).PutEncrypted(
			[]byte("other"), []byte("v"),
		)
	}))
}

func TestRewriteFile_CopiesTree(t *testing.T) {
	cases := []struct {
		name   string
		txSize int
	}{
		{"one transaction", 1 << 20},
		{"commit per entry", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			defer func(size int) { copyTxSize = size }(copyTxSize)
			copyTxSize = tc.txSize
			path := filepath.Join(t.TempDir(), "db")

			db, err := bolt.Open(path, 0600, nil)
			a.NoError(err)
			a.NoError(db.Update(func(tx *bolt.Tx) error {
				root, err := tx.CreateBucket([]byte("root"))
				a.NoError(err)
				a.NoError(root.SetSequence(42))
				a.NoError(root.Put([]byte("k"), []byte("v")))
				a.NoError(root.Put([]byte("empty"), []byte{}))
				child, err := root.CreateBucket([]byte("a/b"))
				a.NoError(err)
				a.NoError(child.SetSequence(7))
				a.NoError(child.Put([]byte("ck"), []byte("cv")))
				for i := range 50 {
					a.NoError(child.Put(
						fmt.Appendf(nil, "n%02d", i), []byte("x"),
					))
				}
				grand, err := child.CreateBucket([]byte("c"))
				a.NoError(err)
				a.NoError(grand.Put([]byte("gk"), []byte("gv")))
				return root.Put([]byte("z"), []byte("last"))
			}))

			db, replaced, err := rewriteFile(db, path, nil, rewriteOp{
				update: func(tx *bolt.Tx) error {
					return tx.Bucket([]byte("root")).Put(
						[]byte("new"), []byte("n"),
					)
				},
				mapValue: func(v []byte) []byte {
					return append([]byte("m:"), v...)
				},
			})
			a.NoError(err)
			a.True(replaced)
			defer db.Close()

			a.NoError(db.View(func(tx *bolt.Tx) error {
				root := tx.Bucket([]byte("root"))
				a.NotNil(root)
				a.Equal(uint64(42), root.Sequence())
				a.Equal([]byte("m:v"), root.Get([]byte("k")))
				a.Equal([]byte("m:n"), root.Get([]byte("new")))
				a.Equal([]byte("m:"), root.Get([]byte("empty")))
				a.Equal([]byte("m:last"), root.Get([]byte("z")))
				child := root.Bucket([]byte("a/b"))
				a.NotNil(child)
				a.Equal(uint64(7), child.Sequence())
				a.Equal([]byte("m:cv"), child.Get([]byte("ck")))
				a.Equal([]byte("m:x"), child.Get([]byte("n49")))
				grand := child.Bucket([]byte("c"))
				a.NotNil(grand)
				a.Equal([]byte("m:gv"), grand.Get([]byte("gk")))
				return nil
			}))
		})
	}
}

func TestNewBoltDB_RemovesStaleCopies(t *testing.T) {
	a := require.New(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "db")

	db, err := NewBoltDB(path, []byte("pass"))
	a.NoError(err)
	a.NoError(db.Close())

	stale := filepath.Join(dir, "db.rewrite-123456")
	a.NoError(os.WriteFile(stale, []byte("partial copy"), 0600))
	// Names that a rewrite does not produce are left alone.
	kept := filepath.Join(dir, "db.rewrite-notes")
	a.NoError(os.WriteFile(kept, nil, 0600))

	db, err = NewBoltDB(path, []byte("pass"))
	a.NoError(err)
	a.NoError(db.Close())

	_, err = os.Stat(stale)
	a.ErrorIs(err, os.ErrNotExist)
	_, err = os.Stat(kept)
	a.NoError(err)
}

func TestRotation_ThroughSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symbolic links needs privileges on Windows")
	}
	a := require.New(t)
	dir := t.TempDir()
	realDir := filepath.Join(dir, "real")
	a.NoError(os.Mkdir(realDir, 0700))
	target := filepath.Join(realDir, "db")
	link := filepath.Join(dir, "db")
	a.NoError(os.Symlink(target, link))

	db, err := NewBoltDB(link, []byte("old"))
	a.NoError(err)
	a.NoError(db.Close())
	before := readMeta(t, target)

	db, err = NewBoltDB(link, []byte("old"))
	a.NoError(err)
	a.NoError(db.RotateDataKey([]byte("old"), []byte("new")))
	a.NoError(db.Close())

	info, err := os.Lstat(link)
	a.NoError(err)
	a.NotZero(info.Mode()&os.ModeSymlink, "link must stay a link")
	raw := readFile(t, target)
	a.False(bytes.Contains(raw, before.wrap.wrappedKey), "old key in target")
	a.False(bytes.Contains(raw, before.secretSalt))
	requireOnlyDB(t, realDir)

	db, err = NewBoltDB(link, []byte("new"))
	a.NoError(err)
	a.NoError(db.Close())
}

func TestRotation_RefusedWithoutLockFile(t *testing.T) {
	a := require.New(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "db")
	// A directory where the lock file belongs cannot be opened as a file.
	a.NoError(os.Mkdir(lockPath(path), 0700))

	db, err := NewBoltDB(path, []byte("old"))
	a.NoError(err, "the store still opens")
	defer db.Close()
	a.NoError(db.Command(func(b Namespace) error {
		return b.Sub([]byte(PeersNamespace)).PutEncrypted(
			[]byte("peer"), []byte("peer-data"),
		)
	}))
	before := readFile(t, path)

	a.ErrorIs(db.RotateDataKey([]byte("old"), []byte("new")), errNoLock)
	a.ErrorIs(db.RotatePassphrase([]byte("old"), []byte("new")), errNoLock)
	a.Equal(before, readFile(t, path))
	requirePeerData(t, db)
}
