package storage

import (
	"time"

	"github.com/dgraph-io/badger/v4"

	"github.com/kamune-org/kamune/relay/internal/model"
)

func (c *Command) Delete(ns model.Namespace, name []byte) error {
	return c.tx.Delete(ns.Key(name))
}

func (c *Command) Set(ns model.Namespace, name, value []byte) error {
	return c.tx.Set(ns.Key(name), value)
}

func (c *Command) SetTTL(
	ns model.Namespace, name, value []byte, ttl time.Duration,
) error {
	entry := badger.NewEntry(ns.Key(name), value).WithTTL(ttl)
	return c.tx.SetEntry(entry)
}
