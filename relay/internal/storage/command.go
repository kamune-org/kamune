package storage

import (
	"time"

	"github.com/dgraph-io/badger/v4"
)

func (c *Command) Delete(key []byte) error {
	return c.tx.Delete(key)
}

func (c *Command) Set(key, value []byte) error {
	return c.tx.Set(key, value)
}

func (c *Command) SetTTL(key, value []byte, ttl time.Duration) error {
	entry := badger.NewEntry(key, value).WithTTL(ttl)
	return c.tx.SetEntry(entry)
}
