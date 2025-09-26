package store

import (
	"fmt"

	bolt "go.etcd.io/bbolt"
)

func (s *Store) AddEncrypted(key, value []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketName)
		return bucket.Put(key, s.cipher.Encrypt(value))
	})
}

func (s *Store) GetEncrypted(key []byte) ([]byte, error) {
	var value []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketName)
		data := bucket.Get(key)
		if data == nil {
			return ErrMissing
		}
		var err error
		value, err = s.cipher.Decrypt(data)
		if err != nil {
			return fmt.Errorf("decrypt: %w", err)
		}
		return nil
	})
	return value, err
}
