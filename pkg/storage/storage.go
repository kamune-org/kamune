package storage

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"time"

	"golang.org/x/term"

	"github.com/kamune-org/kamune/internal/store"
	"github.com/kamune-org/kamune/pkg/attest"
)

var (
	ErrMissingChatBucket = errors.New("chat bucket not found")

	defaultBucket     = []byte(store.DefaultBucket)
	sessionMetaKey    = []byte("name")
	sessionMetaBucket = "session_meta"
)

// SessionSummary holds a session ID together with its first and last message
// timestamps, as read from the database. It is returned by
// ListSessionsByRecent so callers don't need to load full chat histories.
type SessionSummary struct {
	FirstMessage time.Time
	LastMessage  time.Time
	ID           string
	Name         string
	MessageCount int
}

type Sender uint16

const (
	SenderLocal Sender = iota
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
	// NOTE: Passing secrets via env vars has security tradeoffs; prefer OS
	// keychain integration long-term.
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

	slog.Debug("opening kamune storage", slog.String("db_path", s.dbPath))

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

// PublicKey returns the marshalled public key from the stored identity.
// It returns an error if no identity has been created yet.
func (s *Storage) PublicKey() ([]byte, error) {
	at, err := s.Attester()
	if err != nil {
		return nil, fmt.Errorf("loading attester: %w", err)
	}
	return at.PublicKey().Marshal(), nil
}

func (s *Storage) Algorithm() attest.Algorithm {
	return s.algorithm
}

func (s *Storage) Attester() (attest.Attester, error) {
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
	err := s.store.Query(func(q store.Query) error {
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
	if err != nil {
		return nil, fmt.Errorf("querying chat history: %w", err)
	}

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
// ListSessions returns a list of session IDs that have chat history stored.
// Session IDs are extracted from bucket names with the "chat_" prefix.
func (s *Storage) ListSessions() ([]string, error) {
	var sessions []string
	err := s.store.Query(func(q store.Query) error {
		buckets := q.ListBucketsWithPrefix("chat_")
		for _, bucket := range buckets {
			// Remove "chat_" prefix to get session ID
			if len(bucket) > 5 {
				sessions = append(sessions, bucket[5:])
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("listing sessions: %w", err)
	}
	return sessions, nil
}

// SessionTimestamps returns the first and last message timestamps for the
// given session by reading only the first and last keys in its chat bucket.
// This is an O(1) operation per session (two cursor seeks) and avoids loading
// every entry. If the bucket is empty or does not exist both timestamps are
// zero-valued.
func (s *Storage) SessionTimestamps(sessionID string) (
	first, last time.Time, count int, err error,
) {
	bucket := []byte("chat_" + sessionID)
	err = s.store.Query(func(q store.Query) error {
		firstKey := q.FirstKey(bucket)
		lastKey := q.LastKey(bucket)
		if l := len(firstKey); l != 0 && l >= 8 {
			first = time.Unix(0, int64(binary.BigEndian.Uint64(firstKey[:8])))
		}
		if l := len(lastKey); l != 0 && l >= 8 {
			last = time.Unix(0, int64(binary.BigEndian.Uint64(lastKey[:8])))
		}
		// Use BoltDB bucket stats for an efficient key count (no iteration).
		count = q.BucketKeyCount(bucket)
		return nil
	})
	return
}

// ListSessionsByRecent returns summaries for every stored session, sorted by
// the most recent message first (descending LastMessage). Timestamps and
// counts are obtained via cursor seeks and key iteration — no chat payloads
// are decrypted.
func (s *Storage) ListSessionsByRecent() ([]SessionSummary, error) {
	ids, err := s.ListSessions()
	if err != nil {
		return nil, err
	}

	summaries := make([]SessionSummary, 0, len(ids))
	for _, id := range ids {
		first, last, count, err := s.SessionTimestamps(id)
		if err != nil {
			slog.Warn(
				"skipping session with unreadable timestamps",
				slog.String("session_id", id), slog.Any("error", err),
			)
			continue
		}
		name, _ := s.GetSessionName(id)
		summaries = append(summaries, SessionSummary{
			ID:           id,
			FirstMessage: first,
			LastMessage:  last,
			MessageCount: count,
			Name:         name,
		})
	}

	slices.SortFunc(summaries, func(a, b SessionSummary) int {
		return b.LastMessage.Compare(a.LastMessage)
	})

	return summaries, nil
}

// GetSessionName returns the user-assigned display name for a session. If no
// name has been set, an empty string is returned with a nil error.
func (s *Storage) GetSessionName(sessionID string) (string, error) {
	bucket := []byte(sessionMetaBucket + "_" + sessionID)
	var name string
	err := s.store.Query(func(q store.Query) error {
		data, err := q.GetEncrypted(bucket, sessionMetaKey)
		if err != nil {
			return err
		}
		name = string(data)
		return nil
	})
	if err != nil {
		// Missing bucket or key just means no name set yet.
		if errors.Is(err, store.ErrMissingBucket) || errors.Is(err, store.ErrMissingItem) {
			return "", nil
		}
		return "", fmt.Errorf("get session name for %s: %w", sessionID, err)
	}
	return name, nil
}

// SetSessionName persists a user-assigned display name for a session. Pass an
// empty string to clear the name.
func (s *Storage) SetSessionName(sessionID, name string) error {
	bucket := []byte(sessionMetaBucket + "_" + sessionID)
	if name == "" {
		// Remove the key (and tolerate a missing bucket).
		err := s.store.Command(func(c store.Command) error {
			return c.Delete(bucket, sessionMetaKey)
		})
		if err != nil && !errors.Is(err, store.ErrMissingBucket) {
			return fmt.Errorf("clear session name for %s: %w", sessionID, err)
		}
		return nil
	}
	err := s.store.Command(func(c store.Command) error {
		return c.AddEncrypted(bucket, sessionMetaKey, []byte(name))
	})
	if err != nil {
		return fmt.Errorf("set session name for %s: %w", sessionID, err)
	}
	return nil
}

// DeleteSession removes the entire chat history bucket for the given session ID.
func (s *Storage) DeleteSession(sessionID string) error {
	chatBucket := []byte("chat_" + sessionID)
	metaBucket := []byte(sessionMetaBucket + "_" + sessionID)
	err := s.store.Command(func(c store.Command) error {
		if err := c.DeleteBucket(chatBucket); err != nil {
			return err
		}
		// Clean up the metadata bucket as well; ignore missing bucket
		// errors because the session may never have been renamed.
		if err := c.DeleteBucket(metaBucket); err != nil &&
			!errors.Is(err, store.ErrMissingBucket) {
			return err
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("delete session %s: %w", sessionID, err)
	}
	return nil
}

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
