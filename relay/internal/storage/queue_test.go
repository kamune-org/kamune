package storage

import (
	"bytes"
	"fmt"
	"log/slog"
	"testing"

	"github.com/kamune-org/kamune/relay/internal/config"
	"github.com/kamune-org/kamune/relay/internal/model"
	"github.com/stretchr/testify/assert"
)

func openInMemoryStore(t *testing.T) *Store {
	t.Helper()
	cfg := config.Storage{
		Path:     "", // not used when InMemory is true
		InMemory: true,
		LogLevel: slog.LevelError,
	}
	s, err := Open(cfg)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	return s
}

func TestQueue_PushPopOrder(t *testing.T) {
	a := assert.New(t)
	s := openInMemoryStore(t)
	defer s.Close()

	qname := []byte("q-order")
	items := [][]byte{
		[]byte("first"),
		[]byte("second"),
		[]byte("third"),
	}

	// Push items (each push in its own Command transaction)
	for i := range items {
		it := items[i]
		err := s.Command(func(c model.Command) error {
			return c.QPush(qname, it)
		})
		a.NoError(err, "push(%d) should not error", i)
	}

	// Pop and verify order
	for i, expected := range items {
		var got []byte
		err := s.Command(func(c model.Command) error {
			var err error
			got, err = c.QPop(qname)
			if err != nil {
				return err
			}
			return nil
		})
		a.NoError(err, "pop(%d) should not error", i)
		a.Equalf(got, expected, "pop(%d) mismatch: got=%q expected=%q", i, string(got), string(expected))
	}

	// Queue should now be empty (QPop returns (nil, nil) for missing)
	var v []byte
	err := s.Command(func(c model.Command) error {
		var err error
		v, err = c.QPop(qname)
		return err
	})
	a.NoError(err)
	a.Nil(v)
}

func TestQueue_EmptyPop(t *testing.T) {
	a := assert.New(t)
	s := openInMemoryStore(t)
	defer s.Close()

	qname := []byte("q-empty")

	var v []byte
	err := s.Command(func(c model.Command) error {
		var err error
		v, err = c.QPop(qname)
		return err
	})
	a.NoError(err)
	a.Nil(v)
}

func TestQueue_MultipleIndependentQueues(t *testing.T) {
	a := assert.New(t)
	s := openInMemoryStore(t)
	defer s.Close()

	qA := []byte("queue-A")
	qB := []byte("queue-B")

	// push to A and B in a single transaction
	err := s.Command(func(c model.Command) error {
		if err := c.QPush(qA, []byte("a1")); err != nil {
			return err
		}
		if err := c.QPush(qB, []byte("b1")); err != nil {
			return err
		}
		if err := c.QPush(qA, []byte("a2")); err != nil {
			return err
		}
		return nil
	})
	a.NoError(err)

	// Pop A -> expect a1
	var v []byte
	err = s.Command(func(c model.Command) error {
		var err error
		v, err = c.QPop(qA)
		return err
	})
	a.NoError(err)
	a.True(bytes.Equal(v, []byte("a1")))

	// Pop B -> expect b1
	err = s.Command(func(c model.Command) error {
		var err error
		v, err = c.QPop(qB)
		return err
	})
	a.NoError(err)
	a.True(bytes.Equal(v, []byte("b1")))

	// Pop A -> expect a2
	err = s.Command(func(c model.Command) error {
		var err error
		v, err = c.QPop(qA)
		return err
	})
	a.NoError(err)
	a.Equal(string(v), "a2")

	// Now both should be empty and return (nil, nil)
	err = s.Command(func(c model.Command) error {
		var err error
		v, err = c.QPop(qA)
		if err != nil {
			return err
		}
		if v != nil {
			return fmt.Errorf("expected A to be empty, got %v", v)
		}
		v, err = c.QPop(qB)
		if err != nil {
			return err
		}
		if v != nil {
			return fmt.Errorf("expected B to be empty, got %v", v)
		}
		return nil
	})
	a.NoError(err)
}
