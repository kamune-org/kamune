package engine

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestRotation_WaitingOpenSeesNewKey opens a second handle while the first
// rotates the data key. The second open must wait for the first handle to
// close and then fail with the old passphrase, rather than lock and use the
// replaced file.
func TestRotation_WaitingOpenSeesNewKey(t *testing.T) {
	a := require.New(t)
	path := filepath.Join(t.TempDir(), "db")
	oldPass, newPass := []byte("old"), []byte("new")

	db, err := NewBoltDB(path, oldPass)
	a.NoError(err)

	type result struct {
		db  *BoltStore
		err error
	}
	opened := make(chan result, 1)
	go func() {
		s, err := NewBoltDB(path, oldPass, WithTimeout(time.Minute))
		opened <- result{s, err}
	}()
	// Let the second open start waiting for the lock.
	time.Sleep(200 * time.Millisecond)

	a.NoError(db.RotateDataKey(oldPass, newPass))
	select {
	case r := <-opened:
		if r.db != nil {
			r.db.Close()
		}
		a.FailNow("second open finished while the store was held",
			"err: %v", r.err)
	case <-time.After(300 * time.Millisecond):
	}
	a.NoError(db.Close())

	r := <-opened
	if r.db != nil {
		r.db.Close()
	}
	a.ErrorContains(r.err, "decrypt secret")

	db, err = NewBoltDB(path, newPass)
	a.NoError(err)
	a.NoError(db.Close())
}
