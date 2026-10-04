package engine

import (
	"bytes"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"slices"

	bolt "go.etcd.io/bbolt"
	boltErrors "go.etcd.io/bbolt/errors"

	"github.com/kamune-org/kamune/internal/enigma"
)

// boltNamespace is the BoltDB implementation of [Namespace]. Values are
// sealed with their location, path and key (see [valueAD]).
type boltNamespace struct {
	tx     *bolt.Tx
	buck   *bolt.Bucket
	cipher *enigma.Enigma
	name   string
	// path holds the names of the buckets from the root to this one.
	path [][]byte
	// legacy lets values without associated data open, in a store that
	// is not bound yet (see [openValue]).
	legacy bool
}

// child returns the namespace for sub, the bucket called name in b.
func (b *boltNamespace) child(sub *bolt.Bucket, name []byte) *boltNamespace {
	return &boltNamespace{
		tx:     b.tx,
		buck:   sub,
		cipher: b.cipher,
		name:   string(name),
		path:   append(slices.Clip(b.path), bytes.Clone(name)),
		legacy: b.legacy,
	}
}

// newRootNamespace returns the root namespace of tx. With legacy, values
// written without associated data open too.
func newRootNamespace(tx *bolt.Tx, c *enigma.Enigma, legacy bool) Namespace {
	return &boltNamespace{tx: tx, cipher: c, legacy: legacy}
}

// Sub navigates to a child namespace. Unlike [Ensure], it never creates a
// missing namespace — it returns [nilNamespace] instead. This makes Sub safe to
// call inside read-only transactions.
func (b *boltNamespace) Sub(name []byte) Namespace {
	if b == nil {
		return nilNamespace{}
	}

	var sub *bolt.Bucket
	if b.buck == nil {
		sub = b.tx.Bucket(name)
	} else {
		sub = b.buck.Bucket(name)
	}

	if sub == nil {
		return nilNamespace{}
	}

	return b.child(sub, name)
}

// Ensure navigates to a child namespace, creating it if it does not exist. It
// must only be called inside a write transaction ([Store.Command]); calling
// Ensure inside [Store.Query] will return [nilNamespace] because BoltDB read
// transactions cannot create buckets.
func (b *boltNamespace) Ensure(name []byte) Namespace {
	if b == nil {
		return nilNamespace{}
	}

	var sub *bolt.Bucket
	if b.buck == nil {
		sub = b.tx.Bucket(name)
		if sub == nil {
			var err error
			sub, err = b.tx.CreateBucketIfNotExists(name)
			if err != nil {
				slog.Debug(
					"create bucket",
					slog.String("name", string(name)),
					slog.Any("error", err),
				)
				return nilNamespace{}
			}
		}
	} else {
		sub = b.buck.Bucket(name)
		if sub == nil {
			var err error
			sub, err = b.buck.CreateBucketIfNotExists(name)
			if err != nil {
				slog.Debug(
					"create sub-bucket",
					slog.String("name", string(name)),
					slog.Any("error", err),
				)
				return nilNamespace{}
			}
		}
	}

	return b.child(sub, name)
}

func (b *boltNamespace) get(key []byte) ([]byte, error) {
	if b == nil || b.buck == nil {
		return nil, ErrMissingNamespace
	}
	value := b.buck.Get(key)
	if value == nil {
		return nil, ErrMissingItem
	}
	out := make([]byte, len(value))
	copy(out, value)
	return out, nil
}

func (b *boltNamespace) GetEncrypted(key []byte) ([]byte, error) {
	value, err := b.get(key)
	if err != nil {
		return nil, err
	}
	data, err := openValue(b.cipher, b.path, key, value, b.legacy)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return data, nil
}

func (b *boltNamespace) IterateEncrypted() iter.Seq2[[]byte, []byte] {
	return func(yield func(k, v []byte) bool) {
		if b == nil || b.buck == nil {
			return
		}
		c := b.buck.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			kc := make([]byte, len(k))
			copy(kc, k)

			data, err := openValue(b.cipher, b.path, kc, v, b.legacy)
			if err != nil {
				slog.Warn(
					"decrypting value",
					slog.String("namespace", b.name),
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

func (b *boltNamespace) FirstKey() []byte {
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

func (b *boltNamespace) LastKey() []byte {
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

// KeyCount returns the number of keys in the namespace, nested namespaces
// included. It reads every page of the bucket, so its cost grows with the
// size of the namespace.
func (b *boltNamespace) KeyCount() int {
	if b == nil || b.buck == nil {
		return 0
	}
	return b.buck.Stats().KeyN
}

func (b *boltNamespace) ListSubNamespaces() []string {
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

func (b *boltNamespace) put(key, value []byte) error {
	if b == nil || b.buck == nil {
		return ErrMissingNamespace
	}
	if err := b.buck.Put(key, value); err != nil {
		return fmt.Errorf("put: %w", err)
	}
	return nil
}

func (b *boltNamespace) PutEncrypted(key, value []byte) error {
	if b == nil || b.buck == nil {
		return ErrMissingNamespace
	}
	return b.put(key, sealValue(b.cipher, b.path, key, value))
}

func (b *boltNamespace) Delete(key []byte) error {
	if b == nil || b.buck == nil {
		return ErrMissingNamespace
	}
	if err := b.buck.Delete(key); err != nil {
		return fmt.Errorf("delete: %w", err)
	}
	return nil
}

func (b *boltNamespace) DeleteNamespace(name []byte) error {
	if len(name) == 0 {
		return ErrMissingNamespace
	}
	if b == nil || b.buck == nil {
		return ErrMissingNamespace
	}
	if err := b.buck.DeleteBucket(name); err != nil {
		if errors.Is(err, boltErrors.ErrBucketNotFound) {
			return fmt.Errorf(
				"delete namespace %q: %w", name, ErrMissingNamespace,
			)
		}
		return fmt.Errorf("delete namespace %q: %w", name, err)
	}
	return nil
}
