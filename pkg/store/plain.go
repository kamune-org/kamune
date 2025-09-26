package store

import (
	bolt "go.etcd.io/bbolt"
)

func (s *Store) AddPlain(key, value []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketName)
		return bucket.Put(key, value)
	})
}

func (s *Store) GetPlain(key []byte) ([]byte, error) {
	var value []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketName)
		value = bucket.Get(key)
		if value == nil {
			return ErrMissing
		}
		return nil
	})
	return value, err
}
