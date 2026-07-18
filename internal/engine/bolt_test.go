package engine

import (
	"errors"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var (
	_ Store     = (*BoltStore)(nil)
	_ Namespace = (*boltNamespace)(nil)
)

func newTestBoltStore(t *testing.T) *BoltStore {
	t.Helper()
	a := require.New(t)
	f, err := os.CreateTemp("", "engine-bolt-*.db")
	a.NoError(err)
	a.NoError(f.Close())
	t.Cleanup(func() { os.Remove(f.Name()) })
	db, err := NewBoltDB(f.Name(), []byte("test-pass"))
	a.NoError(err)
	t.Cleanup(func() { db.Close() })
	return db
}

func TestBoltStore_Close(t *testing.T) {
	a := require.New(t)
	f, err := os.CreateTemp("", "engine-close-*.db")
	a.NoError(err)
	a.NoError(f.Close())
	defer os.Remove(f.Name())

	db, err := NewBoltDB(f.Name(), []byte(""))
	a.NoError(err)
	a.NoError(db.Close())
}

func TestNewBoltDB_NoCreate(t *testing.T) {
	a := require.New(t)

	_, err := NewBoltDB(
		"/tmp/nonexistent-engine-test.db",
		[]byte("pass"),
		WithCreateIfMissing(false),
	)
	a.Error(err)
	a.True(errors.Is(err, os.ErrNotExist))
}

func TestNewBoltDB_CreateIfMissing(t *testing.T) {
	a := require.New(t)
	f, err := os.CreateTemp("", "engine-create-*.db")
	a.NoError(err)
	a.NoError(f.Close())
	defer os.Remove(f.Name())

	db, err := NewBoltDB(
		f.Name(), []byte("pass"),
		WithCreateIfMissing(true),
	)
	a.NoError(err)
	a.NoError(db.Close())
}

func TestBoltStore_CreatesDefaultNamespaces(t *testing.T) {
	a := require.New(t)
	db := newTestBoltStore(t)

	a.NoError(db.Query(func(b Namespace) error {
		a.NotNil(b.Sub([]byte(DefaultNamespace)))
		a.NotNil(b.Sub([]byte(PeersNamespace)))
		a.NotNil(b.Sub([]byte(SessionsNamespace)))
		a.NotNil(b.Sub([]byte(SettingsNamespace)))
		return nil
	}))
}

func TestPutGetEncrypted(t *testing.T) {
	a := require.New(t)
	db := newTestBoltStore(t)

	a.NoError(db.Command(func(b Namespace) error {
		return b.Sub([]byte(DefaultNamespace)).PutEncrypted(
			[]byte("key1"), []byte("hello world"),
		)
	}))

	a.NoError(db.Query(func(b Namespace) error {
		val, err := b.Sub([]byte(DefaultNamespace)).GetEncrypted([]byte("key1"))
		a.NoError(err)
		a.Equal([]byte("hello world"), val)
		return nil
	}))
}

func TestGetEncrypted_MissingKey(t *testing.T) {
	a := require.New(t)
	db := newTestBoltStore(t)

	a.NoError(db.Query(func(b Namespace) error {
		_, err := b.Sub([]byte(DefaultNamespace)).GetEncrypted([]byte("nope"))
		a.ErrorIs(err, ErrMissingItem)
		return nil
	}))
}

func TestGetEncrypted_MissingNamespace(t *testing.T) {
	a := require.New(t)
	db := newTestBoltStore(t)

	a.NoError(db.Query(func(b Namespace) error {
		_, err := b.Sub([]byte("nonexistent")).GetEncrypted([]byte("k"))
		a.ErrorIs(err, ErrMissingNamespace)
		return nil
	}))
}

func TestDelete(t *testing.T) {
	a := require.New(t)
	db := newTestBoltStore(t)

	a.NoError(db.Command(func(b Namespace) error {
		return b.Sub([]byte(DefaultNamespace)).PutEncrypted(
			[]byte("to-delete"), []byte("value"),
		)
	}))

	a.NoError(db.Command(func(b Namespace) error {
		return b.Sub([]byte(DefaultNamespace)).Delete([]byte("to-delete"))
	}))

	a.NoError(db.Query(func(b Namespace) error {
		_, err := b.Sub([]byte(DefaultNamespace)).GetEncrypted([]byte("to-delete"))
		a.ErrorIs(err, ErrMissingItem)
		return nil
	}))
}

func TestSubAndListSubNamespaces(t *testing.T) {
	a := require.New(t)
	db := newTestBoltStore(t)

	a.NoError(db.Command(func(b Namespace) error {
		parent := b.Ensure([]byte("parent-ns"))
		a.NoError(parent.PutEncrypted([]byte("k"), []byte("v")))
		a.NoError(parent.Ensure([]byte("child-a")).PutEncrypted(
			[]byte("ck"), []byte("cv"),
		))
		a.NoError(parent.Ensure([]byte("child-b")).PutEncrypted(
			[]byte("ck"), []byte("cv"),
		))
		return nil
	}))

	a.NoError(db.Query(func(b Namespace) error {
		names := b.Sub([]byte("parent-ns")).ListSubNamespaces()
		sort.Strings(names)
		a.Equal([]string{"child-a", "child-b"}, names)
		return nil
	}))
}

func TestListSubNamespaces_Empty(t *testing.T) {
	a := require.New(t)
	db := newTestBoltStore(t)

	a.NoError(db.Query(func(b Namespace) error {
		names := b.Sub([]byte(DefaultNamespace)).ListSubNamespaces()
		a.Empty(names)
		return nil
	}))
}

func TestDeleteNamespace(t *testing.T) {
	a := require.New(t)
	db := newTestBoltStore(t)

	a.NoError(db.Command(func(b Namespace) error {
		return b.Ensure([]byte("parent-ns")).
			Ensure([]byte("child-ns")).
			PutEncrypted([]byte("k"), []byte("v"))
	}))

	a.NoError(db.Command(func(b Namespace) error {
		return b.Sub([]byte("parent-ns")).DeleteNamespace([]byte("child-ns"))
	}))

	a.NoError(db.Query(func(b Namespace) error {
		names := b.Sub([]byte("parent-ns")).ListSubNamespaces()
		a.Empty(names)
		return nil
	}))
}

func TestDeleteNamespace_EmptyName(t *testing.T) {
	a := require.New(t)
	db := newTestBoltStore(t)

	a.NoError(db.Command(func(b Namespace) error {
		err := b.Sub([]byte(DefaultNamespace)).DeleteNamespace(nil)
		a.ErrorIs(err, ErrMissingNamespace)
		return nil
	}))
}

func TestDeleteNamespace_Missing(t *testing.T) {
	a := require.New(t)
	db := newTestBoltStore(t)

	a.NoError(db.Command(func(b Namespace) error {
		err := b.Sub([]byte(DefaultNamespace)).
			DeleteNamespace([]byte("does-not-exist"))
		a.ErrorIs(err, ErrMissingNamespace)
		return nil
	}))
}

func TestKeyCountFirstLast(t *testing.T) {
	a := require.New(t)
	db := newTestBoltStore(t)

	a.NoError(db.Command(func(b Namespace) error {
		ns := b.Ensure([]byte("count-test"))
		a.Equal(0, ns.KeyCount())
		a.Nil(ns.FirstKey())
		a.Nil(ns.LastKey())
		return nil
	}))

	a.NoError(db.Command(func(b Namespace) error {
		ns := b.Ensure([]byte("count-test"))
		a.NoError(ns.PutEncrypted([]byte("aaa"), []byte("1")))
		a.NoError(ns.PutEncrypted([]byte("zzz"), []byte("2")))
		a.NoError(ns.PutEncrypted([]byte("mmm"), []byte("3")))
		return nil
	}))

	a.NoError(db.Query(func(b Namespace) error {
		ns := b.Sub([]byte("count-test"))
		a.Equal(3, ns.KeyCount())
		a.Equal([]byte("aaa"), ns.FirstKey())
		a.Equal([]byte("zzz"), ns.LastKey())
		return nil
	}))
}

func TestIterateEncrypted(t *testing.T) {
	a := require.New(t)
	db := newTestBoltStore(t)

	data := map[string]string{
		"alpha": "one",
		"beta":  "two",
		"gamma": "three",
	}

	a.NoError(db.Command(func(b Namespace) error {
		ns := b.Ensure([]byte("iter-test"))
		for k, v := range data {
			a.NoError(ns.PutEncrypted([]byte(k), []byte(v)))
		}
		return nil
	}))

	got := map[string]string{}
	a.NoError(db.Query(func(b Namespace) error {
		ns := b.Sub([]byte("iter-test"))
		for k, v := range ns.IterateEncrypted() {
			got[string(k)] = string(v)
		}
		return nil
	}))
	a.Equal(data, got)
}

func TestIterateEncrypted_EmptyNamespace(t *testing.T) {
	a := require.New(t)
	db := newTestBoltStore(t)

	a.NoError(db.Query(func(b Namespace) error {
		ns := b.Sub([]byte("empty-iter"))
		count := 0
		for range ns.IterateEncrypted() {
			count++
		}
		a.Equal(0, count)
		return nil
	}))
}

func TestChainedSub(t *testing.T) {
	a := require.New(t)
	db := newTestBoltStore(t)

	a.NoError(db.Command(func(b Namespace) error {
		chat := b.Ensure([]byte(SessionsNamespace)).
			Ensure([]byte("sess1")).
			Ensure([]byte("chat"))
		return chat.PutEncrypted([]byte("msg1"), []byte("hello"))
	}))

	a.NoError(db.Query(func(b Namespace) error {
		val, err := b.Sub([]byte(SessionsNamespace)).
			Sub([]byte("sess1")).
			Sub([]byte("chat")).
			GetEncrypted([]byte("msg1"))
		a.NoError(err)
		a.Equal([]byte("hello"), val)
		return nil
	}))
}

func TestQueryIsReadOnly(t *testing.T) {
	a := require.New(t)
	db := newTestBoltStore(t)

	err := db.Query(func(b Namespace) error {
		return b.Sub([]byte(DefaultNamespace)).PutEncrypted(
			[]byte("k"), []byte("v"),
		)
	})
	a.Error(err)
}

func TestRotatePassphrase(t *testing.T) {
	a := require.New(t)
	db := newTestBoltStore(t)

	a.NoError(db.Command(func(b Namespace) error {
		return b.Sub([]byte(DefaultNamespace)).PutEncrypted(
			[]byte("secret"), []byte("my-secret-data"),
		)
	}))

	a.NoError(db.RotatePassphrase(
		[]byte("test-pass"), []byte("new-pass"),
	))

	a.NoError(db.Query(func(b Namespace) error {
		val, err := b.Sub([]byte(DefaultNamespace)).GetEncrypted([]byte("secret"))
		a.NoError(err)
		a.Equal([]byte("my-secret-data"), val)
		return nil
	}))
}

func TestRotatePassphrase_WrongOldPass(t *testing.T) {
	a := require.New(t)
	db := newTestBoltStore(t)

	err := db.RotatePassphrase([]byte("wrong"), []byte("new"))
	a.Error(err)
}

func TestRotateDataKey(t *testing.T) {
	a := require.New(t)
	db := newTestBoltStore(t)
	pass := []byte("test-pass")

	a.NoError(db.Command(func(b Namespace) error {
		if err := b.Sub([]byte(DefaultNamespace)).PutEncrypted(
			[]byte("k1"), []byte("value1"),
		); err != nil {
			return err
		}
		return b.Sub([]byte(PeersNamespace)).PutEncrypted(
			[]byte("pk1"), []byte("peer-data"),
		)
	}))

	a.NoError(db.RotateDataKey(pass, pass))

	a.NoError(db.Query(func(b Namespace) error {
		val, err := b.Sub([]byte(DefaultNamespace)).GetEncrypted([]byte("k1"))
		a.NoError(err)
		a.Equal([]byte("value1"), val)

		val, err = b.Sub([]byte(PeersNamespace)).
			GetEncrypted([]byte("pk1"))
		a.NoError(err)
		a.Equal([]byte("peer-data"), val)
		return nil
	}))
}

func TestRotateDataKey_PreservesOrder(t *testing.T) {
	a := require.New(t)
	db := newTestBoltStore(t)
	pass := []byte("test-pass")

	a.NoError(db.Command(func(b Namespace) error {
		ns := b.Ensure([]byte("order-test"))
		for _, k := range []string{"aaa", "bbb", "ccc", "ddd"} {
			if err := ns.PutEncrypted([]byte(k), []byte("v-"+k)); err != nil {
				return err
			}
		}
		return nil
	}))

	a.NoError(db.RotateDataKey(pass, pass))

	a.NoError(db.Query(func(b Namespace) error {
		ns := b.Sub([]byte("order-test"))
		var keys []string
		for k := range ns.IterateEncrypted() {
			keys = append(keys, string(k))
		}
		a.Equal([]string{"aaa", "bbb", "ccc", "ddd"}, keys)

		for _, k := range keys {
			val, err := ns.GetEncrypted([]byte(k))
			a.NoError(err)
			a.Equal([]byte("v-"+k), val)
		}
		return nil
	}))
}

func TestRotateDataKey_WrongOldPass(t *testing.T) {
	a := require.New(t)
	db := newTestBoltStore(t)

	a.NoError(db.Command(func(b Namespace) error {
		return b.Sub([]byte(DefaultNamespace)).PutEncrypted(
			[]byte("k"), []byte("v"),
		)
	}))

	err := db.RotateDataKey([]byte("wrong"), []byte("new"))
	a.Error(err)
}

func TestRotateDataKey_EmptyStore(t *testing.T) {
	a := require.New(t)
	db := newTestBoltStore(t)

	a.NoError(db.RotateDataKey([]byte("test-pass"), []byte("")))
}

func TestRotateDataKey_NestedBuckets(t *testing.T) {
	a := require.New(t)
	db := newTestBoltStore(t)
	pass := []byte("test-pass")

	a.NoError(db.Command(func(b Namespace) error {
		chat := b.Ensure([]byte(SessionsNamespace)).
			Ensure([]byte("sess-1")).
			Ensure([]byte("chat"))
		if err := chat.PutEncrypted([]byte("msg-1"), []byte("hello")); err != nil {
			return err
		}
		if err := chat.PutEncrypted([]byte("msg-2"), []byte("world")); err != nil {
			return err
		}

		meta := b.Ensure([]byte(SessionsNamespace)).
			Ensure([]byte("sess-1")).
			Ensure([]byte("meta"))
		return meta.PutEncrypted([]byte("established"), []byte("2026-01-01"))
	}))

	a.NoError(db.RotateDataKey(pass, pass))

	a.NoError(db.Query(func(b Namespace) error {
		chat := b.Sub([]byte(SessionsNamespace)).
			Sub([]byte("sess-1")).
			Sub([]byte("chat"))

		val, err := chat.GetEncrypted([]byte("msg-1"))
		a.NoError(err)
		a.Equal([]byte("hello"), val)

		val, err = chat.GetEncrypted([]byte("msg-2"))
		a.NoError(err)
		a.Equal([]byte("world"), val)

		meta := b.Sub([]byte(SessionsNamespace)).
			Sub([]byte("sess-1")).
			Sub([]byte("meta"))
		val, err = meta.GetEncrypted([]byte("established"))
		a.NoError(err)
		a.Equal([]byte("2026-01-01"), val)
		return nil
	}))
}

func TestRotateDataKey_SurvivesRestart(t *testing.T) {
	a := require.New(t)

	f, err := os.CreateTemp("", "engine-restart-*.db")
	a.NoError(err)
	a.NoError(f.Close())
	defer os.Remove(f.Name())

	pass := []byte("restart-pass")

	db, err := NewBoltDB(f.Name(), pass)
	a.NoError(err)

	a.NoError(db.Command(func(b Namespace) error {
		return b.Sub([]byte(PeersNamespace)).PutEncrypted(
			[]byte("pk1"), []byte("peer-data"),
		)
	}))

	a.NoError(db.RotateDataKey(pass, pass))
	a.NoError(db.Close())

	db2, err := NewBoltDB(f.Name(), pass)
	a.NoError(err)
	defer db2.Close()

	a.NoError(db2.Query(func(b Namespace) error {
		val, err := b.Sub([]byte(PeersNamespace)).GetEncrypted([]byte("pk1"))
		a.NoError(err)
		a.Equal([]byte("peer-data"), val)
		return nil
	}))
}

func TestNewBoltDB_WithTimeout(t *testing.T) {
	a := require.New(t)
	f, err := os.CreateTemp("", "engine-timeout-*.db")
	a.NoError(err)
	a.NoError(f.Close())
	defer os.Remove(f.Name())

	db, err := NewBoltDB(f.Name(), []byte("pass"), WithTimeout(10*time.Second))
	a.NoError(err)
	a.NoError(db.Close())
}

func TestOption_NegativeTimeout(t *testing.T) {
	a := require.New(t)
	f, err := os.CreateTemp("", "engine-neg-timeout-*.db")
	a.NoError(err)
	a.NoError(f.Close())
	defer os.Remove(f.Name())

	_, err = NewBoltDB(f.Name(), []byte("pass"), WithTimeout(-1*time.Second))
	a.Error(err)
}

func TestEnsure(t *testing.T) {
	a := require.New(t)
	db := newTestBoltStore(t)

	a.NoError(db.Command(func(b Namespace) error {
		ns := b.Ensure([]byte("ensure-test"))
		a.NoError(ns.PutEncrypted([]byte("k"), []byte("v")))

		// Ensure on existing namespace returns the same handle.
		ns2 := b.Ensure([]byte("ensure-test"))
		val, err := ns2.GetEncrypted([]byte("k"))
		a.NoError(err)
		a.Equal([]byte("v"), val)
		return nil
	}))

	a.NoError(db.Query(func(b Namespace) error {
		val, err := b.Sub([]byte("ensure-test")).GetEncrypted([]byte("k"))
		a.NoError(err)
		a.Equal([]byte("v"), val)
		return nil
	}))
}

func TestSubReadOnly(t *testing.T) {
	a := require.New(t)
	db := newTestBoltStore(t)

	a.NoError(db.Command(func(b Namespace) error {
		ns := b.Ensure([]byte("sub-ro-test"))
		return ns.PutEncrypted([]byte("k"), []byte("v"))
	}))

	a.NoError(db.Query(func(b Namespace) error {
		// Existing namespace: Sub navigates fine.
		ns := b.Sub([]byte("sub-ro-test"))
		val, err := ns.GetEncrypted([]byte("k"))
		a.NoError(err)
		a.Equal([]byte("v"), val)

		// Missing namespace: Sub returns nilNamespace, no error.
		missing := b.Sub([]byte("does-not-exist"))
		val, err = missing.GetEncrypted([]byte("k"))
		a.ErrorIs(err, ErrMissingNamespace)
		a.Nil(val)
		return nil
	}))
}
