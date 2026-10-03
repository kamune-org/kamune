//go:build aix || !(unix || windows)

package engine

import "os"

// tryLockFile does nothing on platforms without flock or LockFileEx; only
// bolt's own lock on the database file applies there.
func tryLockFile(*os.File) (bool, error) { return true, nil }

func unlockFile(*os.File) error { return nil }
