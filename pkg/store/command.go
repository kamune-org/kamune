package store

import (
	"fmt"
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
