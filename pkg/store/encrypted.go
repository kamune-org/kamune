package store

import (
	bolt "go.etcd.io/bbolt"
)

func (s *Store) AddEncrypted(key, value []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		return bucket.Put(s.cipher.Encrypt(key), s.cipher.Encrypt(value))
	})
}

func (s *Store) RemoveEncrypted(key []byte) {
	_ = s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketName)).Delete(s.cipher.Encrypt(key))
	})
}

func (s *Store) GetEncrypted(key []byte) ([]byte, error) {
	var value []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		value = bucket.Get(s.cipher.Encrypt(key))
		if value == nil {
			return ErrMissing
		}
		return nil
	})
	return value, err
}
