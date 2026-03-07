package store

import (
	"errors"
	"fmt"

	boltErrors "go.etcd.io/bbolt/errors"
)

func (c *Command) AddPlain(bucket, key, value []byte) error {
	if len(bucket) == 0 {
		bucket = []byte(DefaultBucket)
	}
	b := c.tx.Bucket(bucket)
	if b == nil {
		var err error
		b, err = c.tx.CreateBucket(bucket)
		if err != nil {
			return fmt.Errorf("create bucket %q: %w", bucket, err)
		}
	}
	if err := b.Put(key, value); err != nil {
		return fmt.Errorf("put: %w", err)
	}
	return nil
}

func (c *Command) AddEncrypted(bucket, key, value []byte) error {
	return c.AddPlain(bucket, key, c.store.cipher.Encrypt(value))
}

func (c *Command) CreateBucket(name []byte) error {
	_, err := c.tx.CreateBucket(name)
	return err
}

// DeleteBucket removes an entire bucket and all of its contents.
// If the bucket does not exist, ErrMissingBucket is returned (wrapped)
// so callers can check with errors.Is(err, ErrMissingBucket).
func (c *Command) DeleteBucket(name []byte) error {
	if len(name) == 0 {
		return ErrMissingBucket
	}
	if err := c.tx.DeleteBucket(name); err != nil {
		if errors.Is(err, boltErrors.ErrBucketNotFound) {
			return fmt.Errorf("delete bucket %q: %w", name, ErrMissingBucket)
		}
		return fmt.Errorf("delete bucket %q: %w", name, err)
	}
	return nil
}

func (c *Command) Delete(bucket, key []byte) error {
	if len(bucket) == 0 {
		bucket = []byte(DefaultBucket)
	}
	b := c.tx.Bucket(bucket)
	if b == nil {
		return ErrMissingBucket
	}
	if err := b.Delete(key); err != nil {
		return fmt.Errorf("delete: %w", err)
	}
	return nil
}

// DeleteBatch removes multiple keys from the same bucket in a single
// transaction. Keys that do not exist are silently skipped.
func (c *Command) DeleteBatch(bucket []byte, keys [][]byte) (int, error) {
	if len(bucket) == 0 {
		bucket = []byte(DefaultBucket)
	}
	b := c.tx.Bucket(bucket)
	if b == nil {
		return 0, ErrMissingBucket
	}
	deleted := 0
	for _, key := range keys {
		if err := b.Delete(key); err != nil {
			return deleted, fmt.Errorf("delete key: %w", err)
		}
		deleted++
	}
	return deleted, nil
}
