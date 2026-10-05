package storage

import (
	"bytes"
	"crypto/hmac"
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
// backends without importing internal packages. A backend that also
// implements Compacter is compacted by [Storage.Compact].
type (
	Store     = engine.Store
	Namespace = engine.Namespace
	Compacter = engine.Compacter
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
	// ErrCompactFailed is returned, wrapping the cause, by
	// [Storage.Compact], and by [Storage.DeleteSession] and
	// [Storage.DeletePeer] when the record was deleted but the database
	// could not be compacted afterwards. The deleted data may then still
	// be in the database file until a compaction succeeds: the next
	// [OpenStorage] tries again, and so can [Storage.Compact].
	ErrCompactFailed = errors.New("could not compact the database")
	// ErrUnsupportedFormat is returned by [OpenStorage] for a database
	// written in a newer layout than this version of the package knows.
	ErrUnsupportedFormat = errors.New("database format is not supported")
	// ErrUpgradeFailed is returned by [OpenStorage], wrapping the cause,
	// for a database written by an older version whose key wrapping and
	// values could not be upgraded, for example because the disk is full
	// or the lock file next to the database cannot be created. Its layout
	// is then not upgraded either, so the older version can still open
	// it. Every open tries the upgrade again.
	ErrUpgradeFailed = errors.New("could not upgrade the database")

	sessionMetaKey = []byte("name")

	// valueMagic starts the value of a chat entry under a legacy key that
	// also holds the sender's timestamp, as opposed to the raw message data
	// of older entries. New entries use [chatValueMagic].
	valueMagic = []byte("KMNE\x01")
)

// messageCountKey holds, in a session's meta namespace, the number of
// entries in its chat namespace as a big-endian uint64.
const messageCountKey = "message_count"

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
	// is in the order messages were stored, which is the order of
	// Timestamp unless the clock was set back.
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
	nameKey           []byte
	expiryDuration    time.Duration
	timeout           time.Duration
	idleSessionLimit  int
	createDB          bool
}

// OpenStorage opens the database, creating it unless [WithCreateDB] says
// otherwise. A database written by an older version is brought up to the
// current layout first, and then compacted (see [Storage.Compact]), so the
// first open after an upgrade can take a while. A compaction that fails,
// after an upgrade or after [Storage.DeleteSession] or
// [Storage.DeletePeer], is logged and tried again on every later open
// until it succeeds. Older versions cannot read a database after it has
// been upgraded. Its key wrapping and values are upgraded before its
// layout; if that fails, OpenStorage returns [ErrUpgradeFailed] and leaves
// the database as the older version wrote it. A database written by a
// newer version gives [ErrUnsupportedFormat].
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
		if err := s.prepare(); err != nil {
			return nil, err
		}
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
	if err := s.prepare(); err != nil {
		_ = db.Close()
		return nil, err
	}

	return s, nil
}

// prepare loads the name key and brings the database up to the current
// layout. A database in an older layout is changed only once the engine
// has upgraded its key wrapping and values (see [engine.Upgrader]):
// until then the older version that wrote it can still open it, and it
// must not find a layout it cannot read.
func (s *Storage) prepare() error {
	version, err := s.formatVersion()
	if err != nil {
		return fmt.Errorf("upgrading storage format: %w", err)
	}
	switch {
	case version > storageFormat:
		return fmt.Errorf(
			"upgrading storage format: %w: version %d, supported %d",
			ErrUnsupportedFormat, version, storageFormat,
		)
	case version < storageFormat:
		if u, ok := s.engine.(engine.Upgrader); ok {
			if err := u.UpgradeErr(); err != nil {
				return fmt.Errorf("%w: %w", ErrUpgradeFailed, err)
			}
		}
	}
	if err := s.loadNameKey(); err != nil {
		return err
	}
	if err := s.upgradeFormat(version); err != nil {
		return fmt.Errorf("upgrading storage format: %w", err)
	}
	return nil
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
// key that peers, sessions and settings are named under is kept, so such
// a person can still check a guessed public key, session ID or setting
// name against a later copy of the file. The database file is rewritten
// and atomically replaced, so neither the old wrapped key nor data under
// the old key remain in it. The new file is
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

// Compact rewrites the database file so that it holds only live data.
// Bolt, the default backend, keeps the pages that deletes and updates free
// in the file with their old contents, sealed under the same data key as
// live data, until it reuses them. Compacting writes the live data into a
// new file and atomically renames it over the old one.
//
// [Storage.DeleteSession] and [Storage.DeletePeer] compact on their own,
// and when that fails, every later [OpenStorage] compacts until one
// succeeds; a successful Compact also ends those retries. Other changes,
// such as clearing a session name or a setting, popping a resumption
// token, deleting idle sessions or expired peers, or replacing a value,
// leave the old value in a free page until the next compaction.
// Freed disk blocks of the old file, such as those an SSD remaps, and
// copies of the file made elsewhere, such as backups, are not scrubbed.
//
// Compacting rewrites the whole file and blocks every other use of the
// Storage until it is done. It needs the lock file that the database had
// when it was opened. A backend from [WithBackend] that does not implement
// [Compacter] is left as it is. Errors wrap [ErrCompactFailed]; one that
// also wraps [ErrReopen] means the Storage must be closed and opened
// again.
func (s *Storage) Compact() error {
	mark, pending, err := s.compactMark()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCompactFailed, err)
	}
	if c, ok := s.engine.(engine.Compacter); ok {
		if err := c.Compact(); err != nil {
			return fmt.Errorf("%w: %w", ErrCompactFailed, err)
		}
	}
	if pending {
		s.clearCompactMark(mark)
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

// session returns the namespace of a session, stored under its keyed
// name (see [Storage.sessionName]).
func (s *Storage) session(b engine.Namespace, id string) engine.Namespace {
	return b.Sub([]byte(engine.SessionsNamespace)).Sub(s.sessionName(id))
}

// sessionChat returns the chat sub-namespace for a session.
func (s *Storage) sessionChat(
	b engine.Namespace, sessionID string,
) engine.Namespace {
	return s.session(b, sessionID).Sub([]byte("chat"))
}

// sessionMeta returns the meta sub-namespace for a session.
func (s *Storage) sessionMeta(
	b engine.Namespace, sessionID string,
) engine.Namespace {
	return s.session(b, sessionID).Sub([]byte("meta"))
}

// ensureSession returns the namespace of a session, creating it if needed,
// with the session ID recorded in its meta namespace.
func (s *Storage) ensureSession(
	b engine.Namespace, sessionID string,
) (engine.Namespace, error) {
	session := b.Ensure([]byte(engine.SessionsNamespace)).
		Ensure(s.sessionName(sessionID))
	meta := session.Ensure([]byte("meta"))
	if _, err := meta.GetEncrypted([]byte(sessionIDKey)); err == nil {
		return session, nil
	}
	err := meta.PutEncrypted([]byte(sessionIDKey), []byte(sessionID))
	if err != nil {
		return nil, fmt.Errorf("store session ID: %w", err)
	}
	return session, nil
}

// sessionID returns the ID of the session stored under name, and whether
// it is recorded there and name is its keyed name.
func (s *Storage) sessionID(sessions engine.Namespace, name string) (
	string, bool,
) {
	id, err := sessions.Sub([]byte(name)).Sub([]byte("meta")).
		GetEncrypted([]byte(sessionIDKey))
	if err != nil || !hmac.Equal(s.sessionName(string(id)), []byte(name)) {
		return "", false
	}
	return string(id), true
}

// GetChatHistory returns the decrypted chat entries of the given session,
// stored in its chat namespace by [Storage.AddChatEntry], in the order
// they were stored, so a peer cannot reorder history by the time it puts
// on its messages. Malformed entries are skipped.
//
// Entries stored before index keys existed, and not converted yet, come
// first, ordered by their receive time and then sender. Their key is 14
// bytes:
//   - 8 bytes: UnixNano timestamp (big-endian) — local receive time
//   - 2 bytes: sender ID (big-endian; 0 means local user, 1 means remote user)
//   - 4 bytes: random suffix to avoid collision
//
// Their value is either the payload alone or, from versions that kept the
// sender's timestamp, a 5-byte magic, the 8-byte timestamp and the payload.
func (s *Storage) GetChatHistory(sessionID string) ([]ChatEntry, error) {
	var entries []ChatEntry
	err := s.engine.Query(func(b engine.Namespace) error {
		chat := s.sessionChat(b, sessionID)
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

	return entries, nil
}

// decodeChatEntry decodes the entry stored under key, with value as its
// decrypted value: an index key with a value from [encodeChatValue], or
// a legacy key of at least 14 bytes (see [Storage.GetChatHistory]).
func decodeChatEntry(key, value []byte) (ChatEntry, bool) {
	if isChatIndexKey(key) {
		return decodeChatValue(value)
	}
	if len(key) < legacyChatKeySize {
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

// ListSessions returns the IDs of the stored sessions, in no particular
// order. Each is read from the meta namespace of its session; a session
// whose ID is missing there, or does not match the name it is stored
// under, is skipped.
func (s *Storage) ListSessions() ([]string, error) {
	var ids []string
	err := s.engine.Query(func(b engine.Namespace) error {
		sessions := b.Sub([]byte(engine.SessionsNamespace))
		for _, name := range sessions.ListSubNamespaces() {
			id, ok := s.sessionID(sessions, name)
			if !ok {
				slog.Warn("skipping session without a valid ID")
				continue
			}
			ids = append(ids, id)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("listing sessions: %w", err)
	}
	return ids, nil
}

// FindSessionByPeer returns the session ID whose PeerKey metadata matches the
// given public key (44-byte PKIX form). Returns an empty string when no match
// is found.
func (s *Storage) FindSessionByPeer(pubKey []byte) (string, error) {
	var sessionID string
	err := s.engine.Query(func(b engine.Namespace) error {
		sessions := b.Sub([]byte(engine.SessionsNamespace))
		for _, name := range sessions.ListSubNamespaces() {
			meta := sessions.Sub([]byte(name)).Sub([]byte("meta"))
			data, err := meta.GetEncrypted([]byte(PeerKey))
			if err != nil || !bytes.Equal(data, pubKey) {
				continue
			}
			if id, ok := s.sessionID(sessions, name); ok {
				sessionID = id
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
// given session by reading only the first and last entries in its chat
// bucket, and its message count. Note that these are local receive
// timestamps, not the sender's original timestamps. The count comes from a
// counter that [Storage.AddChatEntry] keeps in the session's meta
// namespace, so this takes two cursor seeks and three reads and does not
// load the other entries. A session whose entries were all stored before
// the counter existed has its entries counted instead, which reads every
// page of its chat bucket; [Storage.ListSessionsByRecent] stores the
// counter for such sessions. If the bucket is empty or does not exist both
// timestamps are zero-valued.
func (s *Storage) SessionTimestamps(sessionID string) (
	first, last time.Time, count int, err error,
) {
	err = s.engine.Query(func(b engine.Namespace) error {
		first, last, count, _ = s.sessionTimestamps(b, sessionID)
		return nil
	})
	return
}

// sessionTimestamps implements [Storage.SessionTimestamps]. counted reports
// that the count was taken by counting entries, as the session has no
// stored counter.
func (s *Storage) sessionTimestamps(b engine.Namespace, sessionID string) (
	first, last time.Time, count int, counted bool,
) {
	chat := s.sessionChat(b, sessionID)
	firstKey := chat.FirstKey()
	first = chatEntryTime(chat, firstKey)
	last = chatEntryTime(chat, chat.LastKey())
	count, ok := messageCount(s.sessionMeta(b, sessionID))
	if !ok && firstKey != nil {
		count, counted = chat.KeyCount(), true
	}
	return first, last, count, counted
}

// chatEntryTime returns the local receive time of the entry under key in
// chat, or the zero time when there is none or it does not decode. Only
// an entry under an index key is decrypted; a legacy key holds the time.
func chatEntryTime(chat engine.Namespace, key []byte) time.Time {
	if !isChatIndexKey(key) {
		if len(key) < 8 {
			return time.Time{}
		}
		return time.Unix(0, int64(binary.BigEndian.Uint64(key[:8])))
	}
	value, err := chat.GetEncrypted(key)
	if err != nil {
		return time.Time{}
	}
	entry, ok := decodeChatValue(value)
	if !ok {
		return time.Time{}
	}
	return entry.Timestamp
}

// messageCount returns the number of chat entries stored in the counter
// of a session's meta namespace, and whether there is a counter.
func messageCount(meta engine.Namespace) (int, bool) {
	v, err := meta.GetEncrypted([]byte(messageCountKey))
	if err != nil || len(v) != 8 {
		return 0, false
	}
	return int(binary.BigEndian.Uint64(v)), true
}

// putMessageCount stores n as the number of chat entries of a session in
// its meta namespace.
func putMessageCount(meta engine.Namespace, n int) error {
	var v [8]byte
	binary.BigEndian.PutUint64(v[:], uint64(n))
	return meta.PutEncrypted([]byte(messageCountKey), v[:])
}

// storeMessageCounts stores a message counter for each of the sessions
// that has chat entries but no counter, so later counts do not have to
// read their whole chat bucket.
func (s *Storage) storeMessageCounts(ids []string) error {
	return s.engine.Command(func(b engine.Namespace) error {
		for _, id := range ids {
			session := s.session(b, id)
			meta := session.Ensure([]byte("meta"))
			if _, ok := messageCount(meta); ok {
				continue
			}
			chat := session.Sub([]byte("chat"))
			if chat.FirstKey() == nil {
				continue
			}
			if err := putMessageCount(meta, chat.KeyCount()); err != nil {
				return fmt.Errorf("session %s: %w", id, err)
			}
		}
		return nil
	})
}

// ListSessionsByRecent returns summaries for every stored session, sorted by
// the most recent message first (descending LastMessage). Timestamps and
// counts are obtained as [Storage.SessionTimestamps] does, which decrypts
// only the first and last entry of each session. Sessions that had to have
// their entries counted get a stored counter afterwards.
func (s *Storage) ListSessionsByRecent() ([]SessionSummary, error) {
	ids, err := s.ListSessions()
	if err != nil {
		return nil, err
	}

	summaries := make([]SessionSummary, 0, len(ids))
	var uncounted []string
	for _, id := range ids {
		var (
			first, last time.Time
			count       int
			counted     bool
		)
		err := s.engine.Query(func(b engine.Namespace) error {
			first, last, count, counted = s.sessionTimestamps(b, id)
			return nil
		})
		if err != nil {
			slog.Warn(
				"skipping session with unreadable timestamps",
				slog.String("session_id", id), slog.Any("error", err),
			)
			continue
		}
		if counted {
			uncounted = append(uncounted, id)
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

	if len(uncounted) > 0 {
		if err := s.storeMessageCounts(uncounted); err != nil {
			slog.Warn(
				"could not store session message counts",
				slog.Any("error", err),
			)
		}
	}

	return summaries, nil
}

// GetSessionName returns the user-assigned display name for a session. If no
// name has been set, an empty string is returned with a nil error.
func (s *Storage) GetSessionName(sessionID string) (string, error) {
	var name string
	err := s.engine.Query(func(b engine.Namespace) error {
		meta := s.sessionMeta(b, sessionID)
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
			meta := s.sessionMeta(b, sessionID)
			return meta.Delete(sessionMetaKey)
		})
		if err != nil && !errors.Is(err, engine.ErrMissingNamespace) {
			return fmt.Errorf("clear session name for %s: %w", sessionID, err)
		}
		return nil
	}
	err := s.engine.Command(func(b engine.Namespace) error {
		meta := s.sessionMeta(b, sessionID)
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
		data, err := settings.GetEncrypted(s.settingName(fullKey))
		if err != nil {
			return err
		}
		v, ok := decodeSetting(data)
		if !ok {
			return errors.New("malformed setting value")
		}
		val = string(v)
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
// multiple apps share the same database. The setting is stored under a
// keyed name (see [Storage.settingName]), with its value padded to a
// multiple of 64 bytes.
func (s *Storage) SetSettings(app, key, value string) error {
	if app == "" {
		return ErrEmptyAppName
	}
	fullKey := app + ":" + key
	k := s.settingName(fullKey)
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
		return settings.PutEncrypted(k, encodeSetting([]byte(value)))
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
//
// The database is then compacted with [Storage.Compact], even when there
// was no such session, so that the deleted messages do not stay in the
// file. If that fails the session is deleted all the same, the error
// wraps [ErrCompactFailed], and the next [OpenStorage] compacts the
// database.
func (s *Storage) DeleteSession(sessionID string) error {
	err := s.engine.Command(func(b engine.Namespace) error {
		sessions := b.Sub([]byte(engine.SessionsNamespace))
		err := sessions.DeleteNamespace(s.sessionName(sessionID))
		if err != nil && !errors.Is(err, engine.ErrMissingNamespace) {
			return err
		}
		return markCompactPending(b)
	})
	if err == nil {
		err = s.Compact()
	}
	if err != nil {
		return fmt.Errorf("delete session %s: %w", sessionID, err)
	}
	return nil
}

// AddChatEntry stores a chat message for the given session ID. The message
// is stored in the chat namespace of the session, which is created if
// needed, so it does not depend on [Storage.CreateSession] having run, nor
// on the peer being stored. The session's message counter is updated in
// the same transaction.
//
// The entry is keyed by the next index of the session (see
// [chatKeyPrefix]), so its key holds neither its time nor its sender. Its
// value holds the local receive time, from the Storage's clock, ts, the
// sender and the payload, padded to one of a few fixed sizes (see
// [encodeChatValue]), and is sealed under the data key. ts is the
// sender's original timestamp, returned as [ChatEntry.SentAt] for display;
// it never orders history. Entries of the session that are still under
// legacy keys are converted first.
func (s *Storage) AddChatEntry(
	sessionID string, payload []byte, ts time.Time, sender Sender,
) error {
	value := encodeChatValue(ChatEntry{
		Timestamp: s.clock.Now(),
		SentAt:    ts,
		Data:      payload,
		Sender:    sender,
	})
	err := s.engine.Command(func(b engine.Namespace) error {
		session, err := s.ensureSession(b, sessionID)
		if err != nil {
			return err
		}
		chat := session.Ensure([]byte("chat"))
		meta := session.Ensure([]byte("meta"))
		// Count the stored entries once for a session that has none.
		// Nothing else in this transaction has changed chat yet.
		count, ok := messageCount(meta)
		if !ok {
			count = chat.KeyCount()
		}
		next, dropped, err := nextChatIndex(chat)
		if err != nil {
			return err
		}
		count = max(count-dropped, 0)
		if err := chat.PutEncrypted(chatIndexKey(next), value); err != nil {
			return err
		}
		return putMessageCount(meta, count+1)
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
