package store

import (
	bolt "go.etcd.io/bbolt"
)

func (s *Store) AddPlain(key, value []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		return bucket.Put(key, value)
	})
}

func (s *Store) RemovePlain(key []byte) {
	_ = s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketName)).Delete(key)
	})
}

func (s *Store) GetPlain(key []byte) ([]byte, error) {
	var value []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		value = bucket.Get(key)
		if value == nil {
			return ErrMissing
		}
		return nil
	})
	return value, err
}
