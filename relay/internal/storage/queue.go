package storage

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/dgraph-io/badger/v4"

	"github.com/kamune-org/kamune/relay/internal/model"
)

var (
	queueNS = model.NewNameSpace("queue")
	qHead   = []byte("head")
	qTail   = []byte("tail")
)

// QPush pushes an item to the named queue. It appends at the tail index.
func (c *Command) QPush(name, value []byte) error {
	tail, err := qGetMetaUint64(c, name, qTail)
	if err != nil {
		return err
	}
	itemKey := qItemKey(name, tail)
	if err := c.tx.Set(itemKey, value); err != nil {
		return fmt.Errorf("setting queue item: %w", err)
	}
	// advance tail
	if err := qSetMetaUint64(c, name, qTail, tail+1); err != nil {
		return fmt.Errorf("advancing queue tail: %w", err)
	}
	return nil
}

// QPop pops the oldest item from the named queue. Returns nil if queue is empty.
func (c *Command) QPop(name []byte) ([]byte, error) {
	head, err := qGetMetaUint64(c, name, qHead)
	if err != nil {
		return nil, err
	}
	tail, err := qGetMetaUint64(c, name, qTail)
	if err != nil {
		return nil, err
	}
	if head >= tail {
		// empty
		return nil, nil
	}
	itemKey := qItemKey(name, head)
	item, err := c.tx.Get(itemKey)
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("getting queue item: %w", err)
	}
	val, err := item.ValueCopy(nil)
	if err != nil {
		return nil, fmt.Errorf("copying queue item value: %w", err)
	}
	if err := c.tx.Delete(itemKey); err != nil {
		return nil, fmt.Errorf("deleting queue item: %w", err)
	}
	// advance head
	if err := qSetMetaUint64(c, name, qHead, head+1); err != nil {
		return nil, fmt.Errorf("advancing queue head: %w", err)
	}
	return val, nil
}

// qMetaKey builds a meta key for a queue: queueNS + name + ':' + meta
func qMetaKey(name, meta []byte) []byte {
	b := strings.Builder{}
	b.Grow(len(name) + 1 + len(meta))
	b.Write(name)
	b.WriteRune(':')
	b.Write(meta)
	return queueNS.Key([]byte(b.String()))
}

// qItemKey builds an item key for a queue: queueNS + name + 8-byte BE index
func qItemKey(name []byte, idx uint64) []byte {
	suffix := make([]byte, len(name)+8)
	copy(suffix, name)
	binary.BigEndian.PutUint64(suffix[len(name):], idx)
	return queueNS.Key(suffix)
}

func qGetMetaUint64(c *Command, name, meta []byte) (uint64, error) {
	key := qMetaKey(name, meta)
	item, err := c.tx.Get(key)
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			// treat missing meta as zero
			return 0, nil
		}
		return 0, fmt.Errorf("getting queue meta %s: %w", meta, err)
	}
	v, err := item.ValueCopy(nil)
	if err != nil {
		return 0, fmt.Errorf("copying queue meta %s: %w", meta, err)
	}
	if len(v) != 8 {
		return 0, fmt.Errorf("invalid queue meta %s length: %d", meta, len(v))
	}
	return binary.BigEndian.Uint64(v), nil
}

func qSetMetaUint64(c *Command, name, meta []byte, v uint64) error {
	key := qMetaKey(name, meta)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, v)
	return c.tx.Set(key, buf)
}
