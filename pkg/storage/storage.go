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

	"github.com/kamune-org/kamune/internal/clock"
	"github.com/kamune-org/kamune/internal/store"
	"github.com/kamune-org/kamune/pkg/attest"
)

var (
	ErrMissingChatBucket = errors.New("chat bucket not found")
	ErrEmptyAppName      = errors.New("app name must not be empty")

	sessionMetaKey = []byte("name")

	// valueMagic is prepended to stored chat values to distinguish the
	// versioned format (sender timestamp embedded in value) from legacy
	// entries that store raw message data only.
	valueMagic = []byte("KMNE\x01")
)

// SessionSummary holds a session ID together with its first and last message
// timestamps, as read from the database. It is returned by ListSessionsByRecent
// so callers don't need to load full chat histories.
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
	clock             clock.Clock
	passphraseHandler PassphraseHandler
	store             *store.Store
	dbPath            string
	expiryDuration    time.Duration
}

func OpenStorage(opts ...StorageOption) (*Storage, error) {
	s := &Storage{
		passphraseHandler: defaultPassphraseHandler,
		expiryDuration:    7 * 24 * time.Hour,
		clock:             clock.Real(),
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
	db, err := store.New(s.dbPath, pass)
	if err != nil {
		return nil, fmt.Errorf("opening kamune db: %w", err)
	}
	s.store = db

	return s, nil
}

func (s *Storage) Close() error {
	return s.store.Close()
}

// PublicKey returns the marshaled public key from the stored identity.
// It returns an error if no identity has been created yet.
func (s *Storage) PublicKey() ([]byte, error) {
	at, err := s.Attester()
	if err != nil {
		return nil, fmt.Errorf("loading attester: %w", err)
	}
	return at.MarshalPublicKey(), nil
}

func (s *Storage) Attester() (*attest.Attest, error) {
	key := []byte("attest")
	var id []byte
	err := s.store.Query(func(b *store.Bucket) error {
		var err error
		id, err = b.Sub([]byte(store.DefaultBucket)).GetEncrypted(key)
		return err
	})
	switch {
	case err == nil:
		return attest.Load(id)
	case errors.Is(err, store.ErrMissingItem):
		// continue
	default:
		return nil, fmt.Errorf("getting identity: %w", err)
	}

	at, err := attest.New()
	if err != nil {
		return nil, fmt.Errorf("new attest: %w", err)
	}
	data, err := at.MarshalPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("marshalling private key: %w", err)
	}
	err = s.store.Command(func(b *store.Bucket) error {
		return b.Sub([]byte(store.DefaultBucket)).PutEncrypted(key, data)
	})
	if err != nil {
		return nil, fmt.Errorf("persisting generated attest: %w", err)
	}

	return at, nil
}

// sessionChat returns the chat sub-bucket for a session.
func sessionChat(b *store.Bucket, sessionID string) *store.Bucket {
	return b.Sub([]byte(store.SessionsBucket)).
		Sub([]byte(sessionID)).
		Sub([]byte("chat"))
}

// sessionMeta returns the meta sub-bucket for a session.
func sessionMeta(b *store.Bucket, sessionID string) *store.Bucket {
	return b.Sub([]byte(store.SessionsBucket)).
		Sub([]byte(sessionID)).
		Sub([]byte("meta"))
}

// GetChatHistory returns decrypted chat entries stored under the chat
// sub-bucket for the given session ID (sessions/<id>/chat/). Keys are
// expected to be 14 bytes total, composed of:
//   - 8 bytes: UnixNano timestamp (big-endian) — local receive time
//   - 2 bytes: sender ID (big-endian; 0 means local user, 1 means remote user)
//   - 4 bytes: random suffix to avoid collision
//
// The sender's original timestamp is extracted from the value envelope (5-byte
// magic + 8-byte timestamp + payload). Results are sorted by timestamp then
// sender.
func (s *Storage) GetChatHistory(sessionID string) ([]ChatEntry, error) {
	var entries []ChatEntry
	err := s.store.Query(func(b *store.Bucket) error {
		chat := sessionChat(b, sessionID)
		for key, value := range chat.IterateEncrypted() {
			if len(key) < 14 {
				continue
			}
			sender := Sender(binary.BigEndian.Uint16(key[8:]))

			ts := time.Unix(0, int64(binary.BigEndian.Uint64(value[5:13])))
			data := value[13:]

			entries = append(entries, ChatEntry{
				Timestamp: ts,
				Data:      data,
				Sender:    sender,
			})
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("querying chat history: %w", err)
	}

	slices.SortFunc(entries, func(a, b ChatEntry) int {
		if c := a.Timestamp.Compare(b.Timestamp); c != 0 {
			return c
		}
		return int(a.Sender) - int(b.Sender)
	})

	return entries, nil
}

// ListSessions returns a list of session IDs stored under the sessions bucket.
func (s *Storage) ListSessions() ([]string, error) {
	var sessions []string
	err := s.store.Query(func(b *store.Bucket) error {
		sessions = b.Sub([]byte(store.SessionsBucket)).ListSubBuckets()
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("listing sessions: %w", err)
	}
	return sessions, nil
}

// FindSessionByPeer returns the session ID whose PeerKey metadata matches the
// given public key (44-byte PKIX form). Returns an empty string when no match
// is found.
func (s *Storage) FindSessionByPeer(pubKey []byte) (string, error) {
	var sessionID string
	err := s.store.Query(func(b *store.Bucket) error {
		sessions := b.Sub(
			[]byte(store.SessionsBucket),
		).ListSubBuckets()
		for _, sid := range sessions {
			meta := sessionMeta(b, sid)
			data, err := meta.GetEncrypted([]byte(PeerKey))
			if err != nil {
				continue
			}
			if bytes.Equal(data, pubKey) {
				sessionID = sid
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf(
			"find session by peer: %w", err,
		)
	}
	return sessionID, nil
}

// SessionTimestamps returns the first and last message timestamps for the
// given session by reading only the first and last keys in its chat bucket.
// Note that these are local receive timestamps from the key, not the sender's
// original timestamps. This is an O(1) operation per session (two cursor
// seeks) and avoids loading every entry. If the bucket is empty or does not
// exist both timestamps are zero-valued.
func (s *Storage) SessionTimestamps(sessionID string) (
	first, last time.Time, count int, err error,
) {
	err = s.store.Query(func(b *store.Bucket) error {
		chat := sessionChat(b, sessionID)
		firstKey := chat.FirstKey()
		lastKey := chat.LastKey()
		if l := len(firstKey); l != 0 && l >= 8 {
			first = time.Unix(0, int64(binary.BigEndian.Uint64(firstKey[:8])))
		}
		if l := len(lastKey); l != 0 && l >= 8 {
			last = time.Unix(0, int64(binary.BigEndian.Uint64(lastKey[:8])))
		}
		count = chat.KeyCount()
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
	var name string
	err := s.store.Query(func(b *store.Bucket) error {
		meta := sessionMeta(b, sessionID)
		data, err := meta.GetEncrypted(sessionMetaKey)
		if err != nil {
			return err
		}
		name = string(data)
		return nil
	})
	if err != nil {
		// Missing bucket or key just means no name set yet.
		if isMissing(err) {
			return "", nil
		}
		return "", fmt.Errorf("get session name for %s: %w", sessionID, err)
	}
	return name, nil
}

// SetSessionName persists a user-assigned display name for a session. Pass an
// empty string to clear the name.
func (s *Storage) SetSessionName(sessionID, name string) error {
	if name == "" {
		// Remove the key (and tolerate a missing bucket).
		err := s.store.Command(func(b *store.Bucket) error {
			meta := sessionMeta(b, sessionID)
			return meta.Delete(sessionMetaKey)
		})
		if err != nil && !errors.Is(err, store.ErrMissingBucket) {
			return fmt.Errorf("clear session name for %s: %w", sessionID, err)
		}
		return nil
	}
	err := s.store.Command(func(b *store.Bucket) error {
		meta := sessionMeta(b, sessionID)
		return meta.PutEncrypted(sessionMetaKey, []byte(name))
	})
	if err != nil {
		return fmt.Errorf("set session name for %s: %w", sessionID, err)
	}
	return nil
}

// GetSettings returns a settings value stored under the given app and key.
// If the key does not exist, an empty string is returned with no error. The
// app namespace prevents collisions when multiple apps share the same database.
func (s *Storage) GetSettings(app, key string) (string, error) {
	if app == "" {
		return "", ErrEmptyAppName
	}
	var val string
	fullKey := app + ":" + key
	err := s.store.Query(func(b *store.Bucket) error {
		settings := b.Sub([]byte(store.SettingsBucket))
		data, err := settings.GetEncrypted([]byte(fullKey))
		if err != nil {
			return err
		}
		val = string(data)
		return nil
	})
	if err != nil {
		if errors.Is(err, store.ErrMissingItem) {
			return "", nil
		}
		return "", fmt.Errorf("get settings %q: %w", key, err)
	}
	return val, nil
}

// SetSettings stores a settings value under the given app and key. Pass an
// empty string to delete the key. The app namespace prevents collisions when
// multiple apps share the same database.
func (s *Storage) SetSettings(app, key, value string) error {
	if app == "" {
		return ErrEmptyAppName
	}
	fullKey := app + ":" + key
	k := []byte(fullKey)
	if value == "" {
		err := s.store.Command(func(b *store.Bucket) error {
			settings := b.Sub([]byte(store.SettingsBucket))
			return settings.Delete(k)
		})
		if err != nil && !errors.Is(err, store.ErrMissingItem) {
			return fmt.Errorf("delete settings %q: %w", key, err)
		}
		return nil
	}
	err := s.store.Command(func(b *store.Bucket) error {
		settings := b.Sub([]byte(store.SettingsBucket))
		return settings.PutEncrypted(k, []byte(value))
	})
	if err != nil {
		return fmt.Errorf("set settings %q: %w", key, err)
	}
	return nil
}

// DeleteSession removes the session sub-bucket (chat, meta, resumption)
// for the given session ID.
func (s *Storage) DeleteSession(sessionID string) error {
	err := s.store.Command(func(b *store.Bucket) error {
		sessions := b.Sub([]byte(store.SessionsBucket))
		if err := sessions.DeleteBucket([]byte(sessionID)); err != nil &&
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

// AddChatEntry stores a chat message for the given session ID. The message
// is stored in sessions/<sessionID>/chat/.
//
// Key (14 bytes, ordered by local receive time):
//   - 8 bytes: local UnixNano timestamp (big-endian) — uses the local clock
//     to avoid ordering issues from sender clock skew
//   - 2 bytes: sender ID (0 = local, 1 = peer)
//   - 4 bytes: random suffix for uniqueness
//
// Value (versioned envelope):
//   - 5 bytes: magic prefix "KMNE\x01"
//   - 8 bytes: sender's original UnixNano timestamp (big-endian)
//   - remaining: message payload
//
// The ts parameter is the sender's original timestamp and is preserved in
// the value for display, separate from the ordering key.
func (s *Storage) AddChatEntry(
	sessionID string, payload []byte, ts time.Time, sender Sender,
) error {
	// Key uses local time to avoid clock skew in ordering
	key := make([]byte, 14)
	binary.BigEndian.PutUint64(key[:8], uint64(s.clock.Now().UnixNano()))
	binary.BigEndian.PutUint16(key[8:], uint16(sender))

	if _, err := rand.Read(key[10:]); err != nil {
		return fmt.Errorf("generate key suffix: %w", err)
	}

	// Encode sender timestamp into value for correct display
	enc := make([]byte, 13+len(payload))
	copy(enc, valueMagic)
	binary.BigEndian.PutUint64(enc[5:], uint64(ts.UnixNano()))
	copy(enc[13:], payload)

	err := s.store.Command(func(b *store.Bucket) error {
		chat := sessionChat(b, sessionID)
		return chat.PutEncrypted(key, enc)
	})
	if err != nil {
		return fmt.Errorf("store chat entry: %w", err)
	}
	return nil
}

type StorageOption func(*Storage)

func WithDBPath(path string) StorageOption {
	return func(p *Storage) { p.dbPath = path }
}

func WithPassphraseHandler(fn PassphraseHandler) StorageOption {
	return func(p *Storage) { p.passphraseHandler = fn }
}

func WithExpiryDuration(duration time.Duration) StorageOption {
	return func(p *Storage) { p.expiryDuration = duration }
}

func WithNoPassphrase() StorageOption {
	return func(p *Storage) {
		p.passphraseHandler = func() ([]byte, error) { return []byte(""), nil }
	}
}

func WithClock(c clock.Clock) StorageOption {
	return func(p *Storage) { p.clock = c }
}
