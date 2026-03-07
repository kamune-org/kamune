package store

import (
	"fmt"
	"iter"
	"log/slog"
	"strings"

	bolt "go.etcd.io/bbolt"
)

func (q *Query) GetPlain(bucket, key []byte) ([]byte, error) {
	if len(bucket) == 0 {
		bucket = []byte(DefaultBucket)
	}
	b := q.tx.Bucket(bucket)
	if b == nil {
		return nil, ErrMissingBucket
	}
	value := b.Get(key)
	if value == nil {
		return nil, ErrMissingItem
	}
	// Return a copy to avoid accidental mutation of the underlying data.
	out := make([]byte, len(value))
	copy(out, value)
	return out, nil
}

func (q *Query) GetEncrypted(bucket, key []byte) ([]byte, error) {
	value, err := q.GetPlain(bucket, key)
	if err != nil {
		return nil, err
	}
	data, err := q.store.cipher.Decrypt(value)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return data, nil
}

func (q *Query) IteratePlain(bucket []byte) iter.Seq2[[]byte, []byte] {
	if len(bucket) == 0 {
		bucket = []byte(DefaultBucket)
	}
	b := q.tx.Bucket(bucket)
	return func(yield func(k, v []byte) bool) {
		if b == nil {
			return
		}
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			// Make copies of k/v to avoid holding references.
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

func (q *Query) IterateEncrypted(bucket []byte) iter.Seq2[[]byte, []byte] {
	plainIter := q.IteratePlain(bucket)
	return func(yield func(k, v []byte) bool) {
		plainIter(func(k, v []byte) bool {
			data, err := q.store.cipher.Decrypt(v)
			if err != nil {
				slog.Warn(
					"decrypting value",
					slog.String("bucket", string(bucket)),
					slog.String("key", string(k)),
					slog.Any("error", err),
				)
				return true
			}
			return yield(k, data)
		})
	}
}

// FirstKey returns the first key in the given bucket, or nil if the bucket
// is empty or does not exist. BoltDB stores keys in sorted byte order, so
// this is the lexicographically smallest key.
func (q *Query) FirstKey(bucket []byte) []byte {
	if len(bucket) == 0 {
		bucket = []byte(DefaultBucket)
	}
	b := q.tx.Bucket(bucket)
	if b == nil {
		return nil
	}
	k, _ := b.Cursor().First()
	if k == nil {
		return nil
	}
	out := make([]byte, len(k))
	copy(out, k)
	return out
}

// LastKey returns the last key in the given bucket, or nil if the bucket
// is empty or does not exist. BoltDB stores keys in sorted byte order, so
// this is the lexicographically largest key.
func (q *Query) LastKey(bucket []byte) []byte {
	if len(bucket) == 0 {
		bucket = []byte(DefaultBucket)
	}
	b := q.tx.Bucket(bucket)
	if b == nil {
		return nil
	}
	k, _ := b.Cursor().Last()
	if k == nil {
		return nil
	}
	out := make([]byte, len(k))
	copy(out, k)
	return out
}

// BucketKeyCount returns the number of keys in the given bucket without
// iterating. It uses BoltDB's internal B+ tree stats for an efficient count.
// Returns 0 if the bucket does not exist.
func (q *Query) BucketKeyCount(bucket []byte) int {
	if len(bucket) == 0 {
		bucket = []byte(DefaultBucket)
	}
	b := q.tx.Bucket(bucket)
	if b == nil {
		return 0
	}
	return b.Stats().KeyN
}

// ListBuckets returns a list of all bucket names in the database
func (q *Query) ListBuckets() []string {
	var buckets []string
	_ = q.tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
		buckets = append(buckets, string(name))
		return nil
	})
	return buckets
}

// ListBucketsWithPrefix returns bucket names that start with the given prefix
func (q *Query) ListBucketsWithPrefix(prefix string) []string {
	var buckets []string
	_ = q.tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
		nameStr := string(name)
		if strings.HasPrefix(nameStr, prefix) {
			buckets = append(buckets, nameStr)
		}
		return nil
	})
	return buckets
}
