package store

import (
	"errors"
	"fmt"
	"iter"
	"log/slog"

	bolt "go.etcd.io/bbolt"
	boltErrors "go.etcd.io/bbolt/errors"

	"github.com/kamune-org/kamune/internal/enigma"
)

// Bucket wraps a BoltDB bucket with optional encryption support.
// It provides navigation (Sub), key-value operations (Get/Put/Delete),
// and iteration (Iterate/IterateEncrypted).
//
// When used via Store.Query, write operations (Put, PutEncrypted, Delete)
// return ErrTxNotWritable. When used via Store.Command, all operations
// are allowed.
type Bucket struct {
	tx     *bolt.Tx
	buck   *bolt.Bucket
	cipher *enigma.Enigma
	name   string
}

func newRootBucket(tx *bolt.Tx, c *enigma.Enigma) *Bucket {
	return &Bucket{tx: tx, cipher: c}
}

// Sub returns a child bucket, creating it if it does not exist.
// In read-only transactions (Query), the bucket must already exist;
// in write transactions (Command), it is created on demand.
// Returns nil only if the bucket does not exist and cannot be created.
func (b *Bucket) Sub(name []byte) *Bucket {
	if b == nil {
		return nil
	}

	var sub *bolt.Bucket
	if b.buck == nil {
		// Root bucket: navigate from transaction root.
		sub = b.tx.Bucket(name)
		if sub == nil {
			var err error
			sub, err = b.tx.CreateBucketIfNotExists(name)
			if err != nil {
				slog.Warn("create bucket", slog.String("name", string(name)), slog.Any("error", err))
				return nil
			}
		}
	} else {
		sub = b.buck.Bucket(name)
		if sub == nil {
			var err error
			sub, err = b.buck.CreateBucketIfNotExists(name)
			if err != nil {
				slog.Warn("create sub-bucket", slog.String("name", string(name)), slog.Any("error", err))
				return nil
			}
		}
	}

	return &Bucket{
		tx:     b.tx,
		buck:   sub,
		cipher: b.cipher,
		name:   string(name),
	}
}

// --- Read operations ---

// Get returns the value for key, or ErrMissingItem if not found.
// Returns ErrMissingBucket if the bucket does not exist.
func (b *Bucket) Get(key []byte) ([]byte, error) {
	if b == nil || b.buck == nil {
		return nil, ErrMissingBucket
	}
	value := b.buck.Get(key)
	if value == nil {
		return nil, ErrMissingItem
	}
	out := make([]byte, len(value))
	copy(out, value)
	return out, nil
}

// GetEncrypted returns the decrypted value for key.
func (b *Bucket) GetEncrypted(key []byte) ([]byte, error) {
	value, err := b.Get(key)
	if err != nil {
		return nil, err
	}
	data, err := b.cipher.Decrypt(value)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return data, nil
}

// Iterate returns an iterator over all key-value pairs in the bucket.
func (b *Bucket) Iterate() iter.Seq2[[]byte, []byte] {
	return func(yield func(k, v []byte) bool) {
		if b == nil || b.buck == nil {
			return
		}
		c := b.buck.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			kc := make([]byte, len(k))
			copy(kc, k)
			vc := make([]byte, len(v))
			copy(vc, v)
			if !yield(kc, vc) {
				return
			}
		}
	}
}

// IterateEncrypted returns an iterator that decrypts each value.
func (b *Bucket) IterateEncrypted() iter.Seq2[[]byte, []byte] {
	return func(yield func(k, v []byte) bool) {
		if b == nil || b.buck == nil {
			return
		}
		c := b.buck.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			kc := make([]byte, len(k))
			copy(kc, k)

			data, err := b.cipher.Decrypt(v)
			if err != nil {
				slog.Warn(
					"decrypting value",
					slog.String("bucket", b.name),
					slog.String("key", string(kc)),
					slog.Any("error", err),
				)
				continue
			}
			if !yield(kc, data) {
				return
			}
		}
	}
}

// FirstKey returns the first (smallest) key, or nil if empty/missing.
func (b *Bucket) FirstKey() []byte {
	if b == nil || b.buck == nil {
		return nil
	}
	k, _ := b.buck.Cursor().First()
	if k == nil {
		return nil
	}
	out := make([]byte, len(k))
	copy(out, k)
	return out
}

// LastKey returns the last (largest) key, or nil if empty/missing.
func (b *Bucket) LastKey() []byte {
	if b == nil || b.buck == nil {
		return nil
	}
	k, _ := b.buck.Cursor().Last()
	if k == nil {
		return nil
	}
	out := make([]byte, len(k))
	copy(out, k)
	return out
}

// KeyCount returns the number of keys in the bucket.
func (b *Bucket) KeyCount() int {
	if b == nil || b.buck == nil {
		return 0
	}
	return b.buck.Stats().KeyN
}

// ListSubBuckets returns the names of all sub-buckets in this bucket.
func (b *Bucket) ListSubBuckets() []string {
	var names []string
	if b == nil || b.buck == nil {
		return names
	}
	c := b.buck.Cursor()
	for k, _ := c.First(); k != nil; k, _ = c.Next() {
		if b.buck.Bucket(k) != nil {
			names = append(names, string(k))
		}
	}
	return names
}

// --- Write operations ---

// put stores a key-value pair without encryption.
// Only used internally by PutEncrypted. The kamune-store bucket writes
// directly via tx.Bucket(), bypassing the Bucket type entirely.
func (b *Bucket) put(key, value []byte) error {
	if b == nil || b.buck == nil {
		return ErrMissingBucket
	}
	if err := b.buck.Put(key, value); err != nil {
		return fmt.Errorf("put: %w", err)
	}
	return nil
}

// PutEncrypted encrypts value and stores it under key.
// All non-default buckets must use this method.
// Returns ErrMissingBucket if the bucket does not exist.
// Returns ErrTxNotWritable when used inside Store.Query.
func (b *Bucket) PutEncrypted(key, value []byte) error {
	if b == nil || b.buck == nil {
		return ErrMissingBucket
	}
	encrypted := b.cipher.Encrypt(value)
	return b.put(key, encrypted)
}

// Delete removes a key from the bucket.
// Returns ErrMissingBucket if the bucket does not exist.
// Returns ErrTxNotWritable when used inside Store.Query.
func (b *Bucket) Delete(key []byte) error {
	if b == nil || b.buck == nil {
		return ErrMissingBucket
	}
	if err := b.buck.Delete(key); err != nil {
		return fmt.Errorf("delete: %w", err)
	}
	return nil
}

// DeleteBucket removes a child bucket by name.
// Returns ErrMissingBucket if the child does not exist.
// Returns ErrTxNotWritable when used inside Store.Query.
func (b *Bucket) DeleteBucket(name []byte) error {
	if len(name) == 0 {
		return ErrMissingBucket
	}
	if b == nil || b.buck == nil {
		return ErrMissingBucket
	}
	if err := b.buck.DeleteBucket(name); err != nil {
		if errors.Is(err, boltErrors.ErrBucketNotFound) {
			return fmt.Errorf("delete bucket %q: %w", name, ErrMissingBucket)
		}
		return fmt.Errorf("delete bucket %q: %w", name, err)
	}
	return nil
}
