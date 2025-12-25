package kamune

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/term"

	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/pkg/store"
)

var (
	ErrMissingChatBucket = errors.New("chat bucket not found")

	defaultBucket = []byte(store.DefaultBucket)
)

type Sender uint16

const (
	SenderLocal Sender = 0 + iota
	SenderPeer
)

// ChatEntry represents a decrypted chat message stored in the DB.
type ChatEntry struct {
	Timestamp time.Time
	Data      []byte
	Sender    Sender
}

type PassphraseHandler func() ([]byte, error)

func defaultPassphraseHandler() ([]byte, error) {
	// Prefer environment variable to avoid stdin prompts in GUI/daemon contexts.
	// NOTE: Passing secrets via env vars has security tradeoffs; prefer OS keychain
	// integration long-term.
	if envPass := os.Getenv("KAMUNE_DB_PASSPHRASE"); envPass != "" {
		return []byte(envPass), nil
	}

	// Backward-compatible fallback for CLI usage.
	fmt.Println("Enter passphrase:")
	pass, err := term.ReadPassword(0)
	if err != nil {
		return nil, err
	}
	return bytes.TrimSpace(pass), nil
}

type Storage struct {
	passphraseHandler PassphraseHandler
	store             *store.Store
	dbPath            string
	algorithm         attest.Algorithm
	expiryDuration    time.Duration
}

func OpenStorage(opts ...StorageOption) (*Storage, error) {
	s := &Storage{
		algorithm:         attest.Ed25519Algorithm,
		passphraseHandler: defaultPassphraseHandler,
		expiryDuration:    7 * 24 * time.Hour,
	}
	for _, opt := range opts {
		opt(s)
	}

	if s.dbPath == "" {
		// Check for KAMUNE_DB_PATH environment variable first
		if envPath := os.Getenv("KAMUNE_DB_PATH"); envPath != "" {
			s.dbPath = envPath
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, fmt.Errorf("getting user's home directory: %w", err)
			}
			s.dbPath = filepath.Join(home, ".config", "kamune", "db")
		}
	}

	// Ensure the parent directory exists
	dir := filepath.Dir(s.dbPath)
	if err := os.MkdirAll(dir, 0740); err != nil {
		return nil, fmt.Errorf("creating database directory %s: %w", dir, err)
	}

	slog.Info("opening kamune storage", slog.String("db_path", s.dbPath))

	pass, err := s.passphraseHandler()
	if err != nil {
		return nil, fmt.Errorf("getting passphrase: %w", err)
	}
	db, err := store.New(pass, s.dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening kamune db: %w", err)
	}
	s.store = db

	return s, nil
}

func (s *Storage) Close() error {
	return s.store.Close()
}

func (s *Storage) attester() (attest.Attester, error) {
	key := []byte(s.algorithm.String())
	var id []byte
	err := s.store.Query(func(q store.Query) error {
		var err error
		id, err = q.GetPlain(defaultBucket, key)
		return err
	})
	switch {
	case err == nil:
		return attest.LoadAttester(s.algorithm, id)
	case errors.Is(err, store.ErrMissingItem):
		// continue
	default:
		return nil, fmt.Errorf("getting identity: %w", err)
	}

	at, err := attest.NewAttester(s.algorithm)
	if err != nil {
		return nil, fmt.Errorf("new %s: %w", s.algorithm, err)
	}
	data, err := at.Save()
	if err != nil {
		return nil, fmt.Errorf("saving key: %w", err)
	}
	err = s.store.Command(func(c store.Command) error {
		return c.AddPlain(defaultBucket, key, data)
	})
	if err != nil {
		return nil, fmt.Errorf("persisting: %w", err)
	}

	return at, nil
}

// GetChatHistory returns decrypted chat entries stored under a bucket specific
// to the session ID. The bucket name used is "chat_<sessionID>" and keys are
// expected to be 14 bytes total, composed of:
//   - 8 bytes: UnixNano timestamp (big-endian)
//   - 2 bytes: sender ID (big-endian; 0 means local user, 1 means remote user)
//   - 4 bytes: random suffix to avoid collision
func (s *Storage) GetChatHistory(sessionID string) ([]ChatEntry, error) {
	var entries []ChatEntry
	_ = s.store.Query(func(q store.Query) error {
		for key, value := range q.IterateEncrypted([]byte("chat_" + sessionID)) {
			if len(key) < 14 {
				continue
			}
			nanos := int64(binary.BigEndian.Uint64(key[:8]))
			sender := Sender(binary.BigEndian.Uint16(key[8:]))
			ts := time.Unix(0, nanos)
			entries = append(entries, ChatEntry{
				Timestamp: ts,
				Data:      value,
				Sender:    sender,
			})
		}

		return nil
	})

	return entries, nil
}

// AddChatEntry stores a chat message for the given session ID. The message
// is stored in a bucket named "chat_<sessionID>" and the key begins with an
// 8-byte big-endian uint64 representation of the timestamp's UnixNano value.
// 2 bytes are used for the sender identity. Currently, 0 means local user, 1
// means remote user. To avoid collisions when two messages have the same
// timestamp, a 4-byte random suffix is appended to the key to avoid collision.
// The session ID is used as the bucket name, which scopes entries per session.
// If the provided timestamp is zero, the current time is used.
func (s *Storage) AddChatEntry(
	sessionID string, payload []byte, ts time.Time, sender Sender,
) error {
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	bucket := []byte("chat_" + sessionID)

	// 8 bytes timestamp + 2 bytes sender identity + 4 bytes random suffix = 14
	key := make([]byte, 14)
	binary.BigEndian.PutUint64(key[:8], uint64(ts.UnixNano()))
	binary.BigEndian.PutUint16(key[8:], uint16(sender))

	if _, err := rand.Read(key[10:]); err != nil {
		return fmt.Errorf("generate key suffix: %w", err)
	}

	err := s.store.Command(func(c store.Command) error {
		return c.AddEncrypted(bucket, key, payload)
	})
	if err != nil {
		return fmt.Errorf("store chat entry: %w", err)
	}
	return nil
}

type StorageOption func(*Storage)

func StorageWithDBPath(path string) StorageOption {
	return func(p *Storage) { p.dbPath = path }
}

func StorageWithPassphraseHandler(fn PassphraseHandler) StorageOption {
	return func(p *Storage) { p.passphraseHandler = fn }
}

func StorageWithAlgorithm(algorithm attest.Algorithm) StorageOption {
	return func(p *Storage) { p.algorithm = algorithm }
}

func StorageWithExpiryDuration(duration time.Duration) StorageOption {
	return func(p *Storage) { p.expiryDuration = duration }
}

func StorageWithNoPassphrase() StorageOption {
	return func(p *Storage) {
		p.passphraseHandler = func() ([]byte, error) { return []byte(""), nil }
	}
}
