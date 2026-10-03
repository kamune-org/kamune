package engine

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	berrors "go.etcd.io/bbolt/errors"
)

// lockRetryInterval is how long acquire waits between attempts, as bolt
// does for its own file lock.
const lockRetryInterval = 50 * time.Millisecond

// lockPath returns the path of the lock file that guards the database at
// path.
func lockPath(path string) string {
	return path + ".lock"
}

// fileLock is an exclusive advisory lock on the file next to a database.
//
// Bolt locks the database file itself, but a rewrite replaces that file:
// it closes the old handle, which releases bolt's lock, renames the copy
// over the path and opens it again. An opener already waiting on bolt's
// lock holds the old, now unlinked, file and would get it as soon as the
// lock is released, with the old key material and with its later writes
// lost. Every [BoltStore] takes this lock before bolt opens the database
// and holds it until it is closed, so an opener waits here and opens the
// file that is current once the store is closed. The lock file is never
// removed; removing it would let two openers lock different files.
//
// Releases that open the database without this lock still only wait on
// bolt's lock. On platforms without flock or LockFileEx the lock does
// nothing and only bolt's lock applies.
type fileLock struct {
	f *os.File
}

// openLock opens or creates the lock file at path without locking it.
func openLock(path string) (*fileLock, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	return &fileLock{f: f}, nil
}

// acquire takes the lock, trying again until timeout passes. A zero
// timeout waits forever, like bolt. It fails with bolt's ErrTimeout so a
// busy store reports the same error as before.
func (l *fileLock) acquire(timeout time.Duration) error {
	start := time.Now()
	for {
		locked, err := tryLockFile(l.f)
		if err != nil {
			return fmt.Errorf("lock %s: %w", l.f.Name(), err)
		}
		if locked {
			return nil
		}
		if timeout != 0 && time.Since(start) > timeout-lockRetryInterval {
			return berrors.ErrTimeout
		}
		time.Sleep(lockRetryInterval)
	}
}

// release unlocks and closes the lock file. It does nothing on a nil lock.
func (l *fileLock) release() error {
	if l == nil {
		return nil
	}
	return errors.Join(unlockFile(l.f), l.f.Close())
}

// lockStore takes the lock of the database at path, waiting up to timeout,
// and then removes copies an interrupted rewrite left behind. When the
// lock file cannot be opened, for example because the directory is read
// only, it logs a warning and returns a nil lock: the store still opens,
// but [BoltStore.rewrite] refuses to replace its file.
func lockStore(path string, timeout time.Duration) (*fileLock, error) {
	lock, err := openLock(lockPath(path))
	if err != nil {
		slog.Warn(
			"opening database without its lock file; "+
				"key changes that rewrite the file are disabled",
			slog.String("path", path),
			slog.Any("error", err),
		)
		return nil, nil
	}
	if err := lock.acquire(timeout); err != nil {
		lock.f.Close()
		return nil, err
	}
	removeStaleCopies(path)
	return lock, nil
}
