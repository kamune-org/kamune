package storage

import (
	"errors"
	"fmt"
	"time"

	"github.com/dgraph-io/badger/v4"

	"github.com/kamune-org/kamune/relay/internal/model"
)

var (
	ErrMissing = errors.New("key not found")
)

func (q *Query) Get(ns model.Namespace, name []byte) ([]byte, error) {
	key := ns.Key(name)
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

func (q *Query) Exists(ns model.Namespace, name []byte) (bool, error) {
	key := ns.Key(name)
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

func (q *Query) TTL(ns model.Namespace, name []byte) (time.Duration, error) {
	key := ns.Key(name)
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
	now := uint64(time.Now().Unix())
	// If the expiration time is in the past or equal to now, treat as expired.
	if expire <= now {
		return 0, nil
	}
	return time.Duration(expire-now) * time.Second, nil
}
