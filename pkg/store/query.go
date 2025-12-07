package store

import (
	"fmt"
	"iter"
	"log/slog"
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
