package storage

import (
	"errors"
	"fmt"
	"time"

	"github.com/dgraph-io/badger/v4"
)

var (
	ErrMissing = errors.New("key not found")
)

func (q *Query) Get(key []byte) ([]byte, error) {
	item, err := q.tx.Get(key)
	if err != nil {
		switch {
		case errors.Is(err, badger.ErrKeyNotFound):
			return nil, ErrMissing
		default:
			return nil, fmt.Errorf("getting key: %w", err)
		}
	}
	value := make([]byte, 0, item.ValueSize())
	value, err = item.ValueCopy(value)
	if err != nil {
		return nil, fmt.Errorf("copying value: %w", err)
	}
	return value, nil
}

func (q *Query) Exists(key []byte) (bool, error) {
	_, err := q.tx.Get(key)
	if err != nil {
		switch {
		case errors.Is(err, badger.ErrKeyNotFound):
			return false, nil
		default:
			return false, fmt.Errorf("getting key: %w", err)
		}
	}
	return true, nil
}

func (q *Query) TTL(key []byte) (time.Duration, error) {
	item, err := q.tx.Get(key)
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return 0, ErrMissing
		}
		return 0, fmt.Errorf("getting key: %w", err)
	}
	expire := item.ExpiresAt()
	if expire == 0 {
		return 0, nil
	}
	return time.Duration(expire-uint64(time.Now().Unix())) * time.Second, nil
}
