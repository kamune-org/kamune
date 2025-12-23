package storage

import (
	"fmt"
	"log/slog"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/hossein1376/grape/slogger"

	"github.com/kamune-org/kamune/relay/internal/config"
	"github.com/kamune-org/kamune/relay/internal/model"
)

type Store struct {
	db *badger.DB
}

func Open(cfg config.Storage) (*Store, error) {
	logger := newLogger(cfg.LogLevel)
	opts := badger.DefaultOptions(cfg.Path).
		WithLogger(logger).
		WithNamespaceOffset(0)
	if cfg.InMemory {
		logger.Warningf("Serving from an in-memory storage")
		logger.Warningf("This is NOT RECOMMENDED!")
		logger.Warningf("It may cause high RAM usage, and data will be lost on shutdown.")
		opts.Dir = ""
		opts.ValueDir = ""
		opts = opts.WithInMemory(true)
	}
	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("openning storage: %w", err)
	}

	go func() {
		defer func() {
			if msg := recover(); msg != nil {
				slog.Error("panic in store gc", slog.Any("panic", msg))
			}
		}()
		err := db.Flatten(runtime.NumCPU())
		if err != nil {
			slog.Warn("flatten db", slogger.Err("error", err))
		}
		ticker := time.NewTicker(5 * time.Minute)
		for range ticker.C {
		again:
			err := db.RunValueLogGC(0.7)
			if err == nil {
				goto again
			}
		}
	}()

	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) Query(f func(q model.Query) error) error {
	return s.db.View(func(tx *badger.Txn) error {
		defer func() {
			if msg := recover(); msg != nil {
				slog.Error(
					"recovered from panic in view transaction",
					slog.Any("panic", msg),
					slog.String("stack", string(debug.Stack())),
				)
			}
		}()
		return f(&Query{db: s.db, tx: tx})
	})
}

func (s *Store) Command(f func(c model.Command) error) error {
	return s.db.Update(func(tx *badger.Txn) error {
		defer func() {
			if msg := recover(); msg != nil {
				slog.Error(
					"recovered from panic in update transaction",
					slog.Any("panic", msg),
					slog.String("stack", string(debug.Stack())),
				)
			}
		}()
		return f(&Command{Query: Query{db: s.db, tx: tx}})
	})
}

type Query struct {
	db *badger.DB
	tx *badger.Txn
}

type Command struct {
	Query
}
