package store

import (
	"fmt"
)

func (q *Query) GetPlain(key []byte) ([]byte, error) {
	bucket := q.tx.Bucket(bucketName)
	value := bucket.Get(key)
	if value == nil {
		return nil, ErrMissing
	}
	return value, nil
}

func (q *Query) GetEncrypted(key []byte) ([]byte, error) {
	value, err := q.GetPlain(key)
	if err != nil {
		return nil, err
	}
	data, err := q.store.cipher.Decrypt(value)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return data, nil
}
