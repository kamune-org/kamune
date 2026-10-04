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
	"runtime"
	"slices"
	"time"

	"github.com/kamune-org/kamune/internal/clock"
	"github.com/kamune-org/kamune/internal/engine"
	"github.com/kamune-org/kamune/pkg/attest"
)

// Store and Namespace are aliases for the interfaces defined in
// internal/engine. They allow external clients to implement custom storage
// backends without importing internal packages.
type (
	Store     = engine.Store
	Namespace = engine.Namespace
)

var (
	ErrMissingChatBucket = errors.New("chat bucket not found")
	ErrEmptyAppName      = errors.New("app name must not be empty")
	// ErrCorruptMetadata is returned by [OpenStorage] when the database's
	// key-wrapping metadata is partly missing or malformed, or missing from
	// a database that already holds data.
	ErrCorruptMetadata = engine.ErrCorruptMetadata
	// ErrWrongPassphrase is returned by [OpenStorage] and
	// [Storage.ChangePassphrase] when the passphrase does not unlock the
	// database. Tampered key metadata gives the same error.
	ErrWrongPassphrase = engine.ErrWrongPassphrase
	// ErrInsecurePermissions is returned by [OpenStorage] when the database
	// file is accessible to other users and its mode cannot be restricted.
	ErrInsecurePermissions = engine.ErrInsecurePermissions
	// ErrReopen is returned by [Storage.ChangePassphrase] when the new
	// passphrase is already in effect on disk but the database could not
	// be opened again. The Storage must be closed, and the database opened
	// again with the new passphrase.
	ErrReopen = engine.ErrReopen

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
	// Timestamp is when the message was stored, by the local clock. History
	// is ordered by it.
	Timestamp time.Time
	// SentAt is the time the sender put on the message. A peer can set it
	// to anything, so it is only for display and never orders history. It
	// is zero for entries stored without it.
	SentAt time.Time
	Data   []byte
	Sender Sender
}

type PassphraseHandler func() ([]byte, error)

func defaultPassphraseHandler() ([]byte, error) {
	if envPass := os.Getenv("KAMUNE_DB_PASSPHRASE"); envPass != "" {
		return []byte(envPass), nil
	}
	return nil, fmt.Errorf("no passphrase provided")
}

// defaultIdleSessionLimit is the number of idle sessions kept per peer
// unless [WithIdleSessionLimit] sets another.
const defaultIdleSessionLimit = 8

type Storage struct {
	clock             clock.Clock
	passphraseHandler PassphraseHandler
	engine            engine.Store
	dbPath            string
	expiryDuration    time.Duration
	timeout           time.Duration
	idleSessionLimit  int
	createDB          bool
}

func OpenStorage(opts ...StorageOption) (*Storage, error) {
	s := &Storage{
		passphraseHandler: defaultPassphraseHandler,
		expiryDuration:    7 * 24 * time.Hour,
		timeout:           5 * time.Second,
		idleSessionLimit:  defaultIdleSessionLimit,
		clock:             clock.Real(),
		createDB:          true,
	}
	for _, opt := range opts {
		opt(s)
	}

	// If a backend was injected via WithBackend, skip BoltDB setup.
	if s.engine != nil {
		return s, nil
	}

	if s.dbPath == "" {
		// Check for KAMUNE_DB_PATH environment variable first
		if envPath := os.Getenv("KAMUNE_DB_PATH"); envPath != "" {
			s.dbPath = envPath
		} else {
			dir, err := defaultDBDir()
			if err != nil {
				return nil, fmt.Errorf("getting user's home directory: %w", err)
			}
			s.dbPath = filepath.Join(dir, "db")
		}
	}

	// Ensure the parent directory exists and only the user can enter it.
	dir := filepath.Dir(s.dbPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("creating database directory %s: %w", dir, err)
	}
	// Older releases created the default directory group-readable. It
	// belongs to kamune alone, so tighten it. A directory the caller chose
	// may be shared on purpose and is left alone; the engine restricts the
	// database file itself to its owner either way.
	if def, err := defaultDBDir(); err == nil && filepath.Clean(dir) == def {
		restrictDirMode(dir)
	}

	slog.Debug("opening kamune storage", slog.String("db_path", s.dbPath))

	pass, err := s.passphraseHandler()
	if err != nil {
		return nil, fmt.Errorf("getting passphrase: %w", err)
	}
	db, err := engine.NewBoltDB(
		s.dbPath,
		pass,
		engine.WithCreateIfMissing(s.createDB),
		engine.WithTimeout(s.timeout),
	)
	if err != nil {
		return nil, fmt.Errorf("opening kamune db: %w", err)
	}
	s.engine = db

	return s, nil
}

// defaultDBDir returns the directory of the default database path.
func defaultDBDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "kamune"), nil
}

// restrictDirMode removes group and other permission bits from dir. Failure
// is logged, not returned, since the database file mode is what protects
// its contents. On Windows these bits do not control access.
func restrictDirMode(dir string) {
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm()&0o077 == 0 {
		return
	}
	if err := os.Chmod(dir, info.Mode().Perm()&0o700); err != nil {
		slog.Warn(
			"could not restrict database directory permissions",
			slog.String("dir", dir),
			slog.Any("error", err),
		)
	}
}

func (s *Storage) Close() error {
	return s.engine.Close()
}

// ChangePassphrase re-encrypts the database under a new data encryption key
// and wraps that key with newPass. oldPass must be the current passphrase;
// otherwise [ErrWrongPassphrase] is returned and nothing changes. An empty
// oldPass or newPass stands for a database without a passphrase, as with
// [WithNoPassphrase].
//
// A new data key is used, rather than re-wrapping the old one, so that
// someone who knows the old passphrase cannot read data written later. The
// database file is rewritten and atomically replaced, so neither the old
// wrapped key nor data under the old key remain in it. The new file is
// owned by the user running the process, with mode 0600. Copies of the old
// file made elsewhere, such as backups or other hard links, still open with
// the old passphrase.
//
// From the next [OpenStorage] on, newPass is required: callers must update
// any saved copy of the passphrase, such as a keychain entry. On error the
// passphrase is unchanged, unless the error wraps [ErrReopen]; then newPass
// is in effect, and the Storage must be closed and the database opened
// again with it.
func (s *Storage) ChangePassphrase(oldPass, newPass []byte) error {
	if err := s.engine.RotateDataKey(oldPass, newPass); err != nil {
		return fmt.Errorf("change passphrase: %w", err)
	}
	return nil
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

// Attester returns the stored identity, creating and storing a new one
// when there is none. Concurrent first calls all return the same stored
// identity.
func (s *Storage) Attester() (*attest.Attest, error) {
	key := []byte("attest")
	var id []byte
	err := s.engine.Query(func(b engine.Namespace) error {
		var err error
		id, err = b.Sub([]byte(engine.DefaultNamespace)).GetEncrypted(key)
		return err
	})
	switch {
	case err == nil:
		return attest.Load(id)
	case errors.Is(err, engine.ErrMissingItem):
		// continue
	default:
		return nil, fmt.Errorf("getting identity: %w", err)
	}

	// Check again in the transaction that writes, so that a concurrent
	// call that created the identity first is not overwritten.
	var created *attest.Attest
	err = s.engine.Command(func(b engine.Namespace) error {
		ns := b.Ensure([]byte(engine.DefaultNamespace))
		var err error
		id, err = ns.GetEncrypted(key)
		if !errors.Is(err, engine.ErrMissingItem) {
			return err
		}
		created, err = attest.New()
		if err != nil {
			return fmt.Errorf("new attest: %w", err)
		}
		id, err = created.MarshalPrivateKey()
		if err != nil {
			return fmt.Errorf("marshalling private key: %w", err)
		}
		return ns.PutEncrypted(key, id)
	})
	if err != nil {
		return nil, fmt.Errorf("persisting generated attest: %w", err)
	}
	if created != nil {
		return created, nil
	}
	return attest.Load(id)
}

// sessionChat returns the chat sub-namespace for a session.
func sessionChat(b engine.Namespace, sessionID string) engine.Namespace {
	return b.Sub([]byte(engine.SessionsNamespace)).
		Sub([]byte(sessionID)).
		Sub([]byte("chat"))
}

// sessionMeta returns the meta sub-namespace for a session.
func sessionMeta(b engine.Namespace, sessionID string) engine.Namespace {
	return b.Sub([]byte(engine.SessionsNamespace)).
		Sub([]byte(sessionID)).
		Sub([]byte("meta"))
}

// sessionMetaEnsure returns the meta sub-namespace, creating it if needed.
func sessionMetaEnsure(
	b engine.Namespace, sessionID string,
) engine.Namespace {
	sessions := b.Ensure([]byte(engine.SessionsNamespace))
	session := sessions.Ensure([]byte(sessionID))
	return session.Ensure([]byte("meta"))
}

// GetChatHistory returns decrypted chat entries stored under the chat
// sub-namespace for the given session ID (sessions/<id>/chat/). Keys are
// expected to be 14 bytes total, composed of:
//   - 8 bytes: UnixNano timestamp (big-endian) — local receive time
//   - 2 bytes: sender ID (big-endian; 0 means local user, 1 means remote user)
//   - 4 bytes: random suffix to avoid collision
//
// Each entry's Timestamp is the local time from its key. Versioned entries
// also carry the sender's timestamp in the value envelope (5-byte magic +
// 8-byte timestamp + payload), returned as SentAt. Legacy entries store
// only the payload. Malformed versioned entries are skipped. Results are
// sorted by Timestamp then sender, so a peer cannot reorder history by
// the time it puts on its messages.
func (s *Storage) GetChatHistory(sessionID string) ([]ChatEntry, error) {
	var entries []ChatEntry
	err := s.engine.Query(func(b engine.Namespace) error {
		chat := sessionChat(b, sessionID)
		for key, value := range chat.IterateEncrypted() {
			entry, ok := decodeChatEntry(key, value)
			if ok {
				entries = append(entries, entry)
			}
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

func decodeChatEntry(key, value []byte) (ChatEntry, bool) {
	if len(key) < 14 {
		return ChatEntry{}, false
	}

	entry := ChatEntry{
		Timestamp: time.Unix(0, int64(binary.BigEndian.Uint64(key[:8]))),
		Data:      value,
		Sender:    Sender(binary.BigEndian.Uint16(key[8:])),
	}
	if bytes.HasPrefix(value, valueMagic) {
		if len(value) < len(valueMagic)+8 {
			return ChatEntry{}, false
		}
		offset := len(valueMagic)
		entry.SentAt = time.Unix(
			0, int64(binary.BigEndian.Uint64(value[offset:offset+8])),
		)
		entry.Data = value[offset+8:]
	}
	entry.Data = bytes.Clone(entry.Data)
	return entry, true
}

// ListSessions returns a list of session IDs stored under the sessions namespace.
func (s *Storage) ListSessions() ([]string, error) {
	var sessions []string
	err := s.engine.Query(func(b engine.Namespace) error {
		sessions = b.Sub([]byte(engine.SessionsNamespace)).ListSubNamespaces()
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
	err := s.engine.Query(func(b engine.Namespace) error {
		sessions := b.Sub([]byte(engine.SessionsNamespace)).ListSubNamespaces()
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
	err = s.engine.Query(func(b engine.Namespace) error {
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
	err := s.engine.Query(func(b engine.Namespace) error {
		meta := sessionMeta(b, sessionID)
		data, err := meta.GetEncrypted(sessionMetaKey)
		if err != nil {
			return err
		}
		name = string(data)
		return nil
	})
	if err != nil {
		// Missing namespace or key just means no name set yet.
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
		// Remove the key (and tolerate a missing namespace).
		err := s.engine.Command(func(b engine.Namespace) error {
			meta := sessionMeta(b, sessionID)
			return meta.Delete(sessionMetaKey)
		})
		if err != nil && !errors.Is(err, engine.ErrMissingNamespace) {
			return fmt.Errorf("clear session name for %s: %w", sessionID, err)
		}
		return nil
	}
	err := s.engine.Command(func(b engine.Namespace) error {
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
	err := s.engine.Query(func(b engine.Namespace) error {
		settings := b.Sub([]byte(engine.SettingsNamespace))
		data, err := settings.GetEncrypted([]byte(fullKey))
		if err != nil {
			return err
		}
		val = string(data)
		return nil
	})
	if err != nil {
		if errors.Is(err, engine.ErrMissingItem) {
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
		err := s.engine.Command(func(b engine.Namespace) error {
			settings := b.Ensure([]byte(engine.SettingsNamespace))
			return settings.Delete(k)
		})
		if err != nil && !errors.Is(err, engine.ErrMissingItem) {
			return fmt.Errorf("delete settings %q: %w", key, err)
		}
		return nil
	}
	err := s.engine.Command(func(b engine.Namespace) error {
		settings := b.Ensure([]byte(engine.SettingsNamespace))
		return settings.PutEncrypted(k, []byte(value))
	})
	if err != nil {
		return fmt.Errorf("set settings %q: %w", key, err)
	}
	return nil
}

// DeleteSession removes the session sub-namespace (chat, meta, resumption)
// for the given session ID. Close a session that is still connected first:
// a message stored for it afterwards with [Storage.AddChatEntry] creates
// its chat again, and the session is listed again with that message.
func (s *Storage) DeleteSession(sessionID string) error {
	err := s.engine.Command(func(b engine.Namespace) error {
		sessions := b.Sub([]byte(engine.SessionsNamespace))
		if err := sessions.DeleteNamespace([]byte(sessionID)); err != nil &&
			!errors.Is(err, engine.ErrMissingNamespace) {
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
// is stored in sessions/<sessionID>/chat/, which is created if needed, so
// it does not depend on [Storage.CreateSession] having run, nor on the
// peer being stored.
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
// The ts parameter is the sender's original timestamp. It is preserved in
// the value and returned as [ChatEntry.SentAt] for display, separate from
// the ordering key.
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

	err := s.engine.Command(func(b engine.Namespace) error {
		chat := b.Ensure([]byte(engine.SessionsNamespace)).
			Ensure([]byte(sessionID)).
			Ensure([]byte("chat"))
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

// WithBackend injects a custom [engine.Store] implementation. When set,
// OpenStorage skips creating a BoltDB and uses the provided backend directly.
// Options like [WithTimeout] and [WithCreateDB] are ignored.
func WithBackend(b engine.Store) StorageOption {
	return func(p *Storage) { p.engine = b }
}

// WithCreateDB controls whether OpenStorage creates the database when it does
// not exist. The default is true.
func WithCreateDB(v bool) StorageOption {
	return func(p *Storage) { p.createDB = v }
}

// WithIdleSessionLimit sets how many idle sessions are kept for each peer.
// A session is idle when it has no chat entries and no name. Every new
// session, from [Storage.CreateSession] or [Storage.PutSessionResumption]
// with setEstablished, counts as idle, and once a peer has more than n idle
// sessions the ones established first are deleted. This bounds what a peer
// adds to the database and the session list by connecting and closing over
// and over, but not what it adds by sending one message in each session:
// sessions with chat entries are never deleted, and the rate of new
// sessions is not limited here.
//
// Storage does not know which sessions are still connected, so an idle
// session that is still connected is deleted too once newer sessions with
// the same peer push it out. [Storage.SetMeta] on it then returns
// [ErrSessionNotFound], and it can no longer be resumed; a resume that had
// already checked its token stores it again, without an established_at.
// Each new session reads every stored session, in the transaction that
// stores it.
//
// n <= 0 keeps every session. The default is 8.
func WithIdleSessionLimit(n int) StorageOption {
	return func(p *Storage) { p.idleSessionLimit = n }
}

// WithTimeout sets the maximum time the backend waits for the database to open
// or connect. A zero value keeps the backend default (5s for BoltDB). Ignored
// when [WithBackend] is used.
func WithTimeout(d time.Duration) StorageOption {
	return func(p *Storage) { p.timeout = d }
}
