package store

import (
	"fmt"
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
	return value, nil
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
