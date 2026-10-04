package engine

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	bolt "go.etcd.io/bbolt"
)

// copyInfix sits between the database file name and the random suffix of
// the copies [rewriteFile] writes.
const copyInfix = ".rewrite-"

// copyTxSize bounds the key and value bytes written to a copy in one
// transaction, as txMaxSize does for bolt.Compact. Bolt keeps the dirty
// pages of a transaction in memory until it commits, so a copy made in a
// single transaction would hold the whole database. It is a variable so
// tests can force many commits.
var copyTxSize = 1 << 20

// rewriteOp is a change made by rewriting the database file.
type rewriteOp struct {
	// update, when set, changes the state to copy. It runs in a write
	// transaction on the old file that is rolled back after the copy.
	update func(*bolt.Tx) error
	// mapValue, when set, is applied to every value as it is copied, with
	// the names of the buckets that hold it and its key. It must not keep
	// or modify its arguments.
	mapValue valueMapper
}

// valueMapper returns the value to copy for key, whose value is value, in
// the bucket at path.
type valueMapper func(path [][]byte, key, value []byte) []byte

// rewriteFile runs op.update in a write transaction on db, writes the state
// it leaves into a new file next to path, passing every value through
// op.mapValue, and atomically renames the new file over path.
//
// Committing the change in place would leave the pages it superseded, such
// as an old wrapped key or values under a retired key, in the file's free
// list until bolt happens to reuse them. The new file holds only live data.
// The transaction on db is always rolled back, so the old file is never
// modified. Freed disk blocks of the old file, and copies of it elsewhere,
// are not scrubbed.
//
// db must be open on path, and path must not be a symbolic link; the
// caller resolves links when it opens the store. The new file is owned by
// the user running the process, with mode 0600. Other hard links to the
// old file, and its extended attributes, are not carried over; a hard link
// keeps the old contents.
//
// Between closing db and opening the new file, bolt's lock on the database
// is not held. The caller must hold the store's [fileLock] so that no other
// store opens the old file in that window.
//
// It returns the handle to use from now on and whether the file was
// replaced. Before the rename, an error leaves the file unchanged and db
// open. After it, db is closed and the reopened handle is returned; if
// reopening fails the handle is nil and the error wraps [ErrReopen].
func rewriteFile(
	db *bolt.DB, path string, opts *bolt.Options, op rewriteOp,
) (*bolt.DB, bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return db, false, fmt.Errorf("stat store file: %w", err)
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return db, false, fmt.Errorf(
			"store file %s is a symbolic link", path,
		)
	}

	tmpPath, err := writeCopy(db, path, op)
	if err != nil {
		return db, false, err
	}

	replaced := false
	err = db.Close()
	if err == nil {
		err = os.Rename(tmpPath, path)
		replaced = err == nil
	}
	if replaced {
		syncDir(filepath.Dir(path))
	} else {
		os.Remove(tmpPath)
		err = fmt.Errorf("replace store file: %w", err)
	}

	reopened, openErr := bolt.Open(path, 0600, opts)
	if openErr != nil {
		return nil, replaced, errors.Join(
			err, fmt.Errorf("%w: %w", ErrReopen, openErr),
		)
	}
	if !replaced {
		return reopened, false, err
	}
	return reopened, true, nil
}

// writeCopy applies op.update in a write transaction on db, copies every
// bucket as it left them into a new file in the directory of path, and
// rolls the transaction back. It returns the path of the copy, which has
// been synced.
func writeCopy(db *bolt.DB, path string, op rewriteOp) (string, error) {
	src, err := db.Begin(true)
	if err != nil {
		return "", fmt.Errorf("begin: %w", err)
	}
	defer src.Rollback()

	if op.update != nil {
		if err := op.update(src); err != nil {
			return "", err
		}
	}

	f, err := os.CreateTemp(
		filepath.Dir(path), filepath.Base(path)+copyInfix+"*",
	)
	if err != nil {
		return "", fmt.Errorf("create copy: %w", err)
	}
	tmpPath := f.Name()
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("create copy: %w", err)
	}

	// The copy is synced once, below, before it can replace the store.
	dst, err := bolt.Open(tmpPath, 0600, &bolt.Options{NoSync: true})
	if err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("open copy: %w", err)
	}
	err = copyTx(dst, src, op.mapValue)
	if err == nil {
		err = dst.Sync()
	}
	if closeErr := dst.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("write copy: %w", err)
	}
	return tmpPath, nil
}

// copier writes buckets into a new database and commits every copyTxSize
// bytes.
type copier struct {
	db       *bolt.DB
	tx       *bolt.Tx
	mapValue valueMapper
	size     int
}

// copyTx copies every bucket of src, with its keys, nested buckets and
// sequences, into dst.
func copyTx(dst *bolt.DB, src *bolt.Tx, mapValue valueMapper) error {
	tx, err := dst.Begin(true)
	if err != nil {
		return err
	}
	c := &copier{db: dst, tx: tx, mapValue: mapValue}
	defer func() {
		if c.tx != nil {
			c.tx.Rollback()
		}
	}()

	err = src.ForEach(func(name []byte, b *bolt.Bucket) error {
		if err := c.reserve(len(name)); err != nil {
			return err
		}
		child, err := c.tx.CreateBucket(name)
		if err != nil {
			return err
		}
		if err := child.SetSequence(b.Sequence()); err != nil {
			return err
		}
		return c.copyBucket([][]byte{name}, b)
	})
	if err != nil {
		return err
	}
	err = c.tx.Commit()
	c.tx = nil
	return err
}

// reserve accounts for n more bytes, first committing the transaction and
// starting a new one when they would take it past copyTxSize.
func (c *copier) reserve(n int) error {
	if c.size > 0 && c.size+n > copyTxSize {
		err := c.tx.Commit()
		c.tx = nil
		if err != nil {
			return err
		}
		if c.tx, err = c.db.Begin(true); err != nil {
			return err
		}
		c.size = 0
	}
	c.size += n
	return nil
}

// bucket returns the bucket at path in the current transaction. A bucket
// handle belongs to one transaction, so it is looked up again each time.
func (c *copier) bucket(path [][]byte) *bolt.Bucket {
	b := c.tx.Bucket(path[0])
	for _, name := range path[1:] {
		b = b.Bucket(name)
	}
	return b
}

// copyBucket copies the keys and nested buckets of src into the bucket at
// path.
func (c *copier) copyBucket(path [][]byte, src *bolt.Bucket) error {
	return src.ForEach(func(k, v []byte) error {
		sub := src.Bucket(k)
		if sub == nil && c.mapValue != nil {
			v = c.mapValue(path, k, v)
		}
		if err := c.reserve(len(k) + len(v)); err != nil {
			return err
		}
		dst := c.bucket(path)
		if sub == nil {
			return dst.Put(k, v)
		}
		child, err := dst.CreateBucket(k)
		if err != nil {
			return err
		}
		if err := child.SetSequence(sub.Sequence()); err != nil {
			return err
		}
		return c.copyBucket(append(slices.Clip(path), k), sub)
	})
}

// removeStaleCopies deletes the copies that rewrites of the database at
// path left behind when they were interrupted, for example by a crash. The
// caller must hold the store's [fileLock], so no rewrite is in progress.
func removeStaleCopies(path string) {
	dir := filepath.Dir(path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	prefix := filepath.Base(path) + copyInfix
	for _, e := range entries {
		suffix, ok := strings.CutPrefix(e.Name(), prefix)
		if !ok || !isDigits(suffix) || !e.Type().IsRegular() {
			continue
		}
		stale := filepath.Join(dir, e.Name())
		if err := os.Remove(stale); err != nil {
			slog.Warn(
				"could not remove interrupted database copy",
				slog.String("path", stale),
				slog.Any("error", err),
			)
			continue
		}
		slog.Info(
			"removed interrupted database copy",
			slog.String("path", stale),
		)
	}
}

// isDigits reports whether s is a non-empty run of ASCII digits, the form
// of the random part os.CreateTemp puts in a name.
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// syncDir makes a rename in dir durable where the platform supports it.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

// resolvePath resolves symbolic links in path, so the lock file sits next
// to the real database and a rewrite replaces the target of a link rather
// than the link. A path that does not exist yet is returned unchanged.
func resolvePath(path string) (string, error) {
	real, err := filepath.EvalSymlinks(path)
	switch {
	case err == nil:
		return real, nil
	case errors.Is(err, fs.ErrNotExist):
		return path, nil
	default:
		return "", err
	}
}
