package storage

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"

	"github.com/kamune-org/kamune/internal/engine"
)

// formatKey, in the default namespace, holds the version of the layout the
// database is in, as one byte sealed under the data key. A database
// without it was written before versions were recorded, and is version 0.
const formatKey = "storage-format"

// compactPendingKey, in the default namespace, marks a database that may
// hold data in free pages that it must not keep: the old layout of an
// upgrade, or what [Storage.DeleteSession] or [Storage.DeletePeer]
// deleted. It is recorded in the transaction that frees the data, under a
// new random value, and removed once a compaction that started after it
// succeeds (see [Storage.Compact]). Each open compacts a database that
// holds it (see [Storage.compactIfPending]).
const compactPendingKey = "compact-pending"

// compactMarkSize is the size of the random value of [compactPendingKey].
const compactMarkSize = 16

// storageFormat is the version of the layout this package writes. Each
// version adds to the one before it:
//   - 1: chat entries are keyed by index, and hold their receive time and
//     sender in their padded value (see [chatKeyPrefix])
//   - 2: peers, sessions and settings are stored under keyed names, and
//     setting values are padded (see [nameKeyKey])
const storageFormat = 2

// upgradeFormat brings the database from version, its recorded layout,
// up to [storageFormat] and records it. Each step can be run again on data
// it already converted, so a step that is interrupted, by a crash or an
// error, is completed on the next open. When a step changed anything, the
// database is compacted afterwards, so that the old layout does not stay
// in free pages. A compaction that is interrupted or fails is tried
// again on every later open until it succeeds.
func (s *Storage) upgradeFormat(version byte) error {
	if version >= storageFormat {
		return s.compactIfPending()
	}

	var changed int
	if version < 1 {
		n, err := s.convertLegacyChats()
		if err != nil {
			return fmt.Errorf("convert chat entries: %w", err)
		}
		changed += n
	}
	if version < 2 {
		n, err := s.keyNames()
		if err != nil {
			return fmt.Errorf("key names: %w", err)
		}
		changed += n
	}
	err := s.engine.Command(func(b engine.Namespace) error {
		def := b.Ensure([]byte(engine.DefaultNamespace))
		if changed > 0 {
			if err := markCompactPending(b); err != nil {
				return err
			}
		}
		return def.PutEncrypted([]byte(formatKey), []byte{storageFormat})
	})
	if err != nil {
		return fmt.Errorf("record format version: %w", err)
	}
	if changed > 0 {
		slog.Info(
			"upgraded database format",
			slog.Int("from", int(version)),
			slog.Int("to", storageFormat),
		)
	}
	return s.compactIfPending()
}

// markCompactPending records [compactPendingKey] in b, under a new random
// value, so that the data the transaction frees is compacted away even if
// the compaction that should follow fails or never runs.
func markCompactPending(b engine.Namespace) error {
	mark := make([]byte, compactMarkSize)
	if _, err := rand.Read(mark); err != nil {
		return fmt.Errorf("mark compaction: %w", err)
	}
	err := b.Ensure([]byte(engine.DefaultNamespace)).
		PutEncrypted([]byte(compactPendingKey), mark)
	if err != nil {
		return fmt.Errorf("mark compaction: %w", err)
	}
	return nil
}

// compactMark returns the value of [compactPendingKey] and whether it is
// set. A mark that does not open is still a mark, with a nil value.
func (s *Storage) compactMark() ([]byte, bool, error) {
	var (
		mark    []byte
		pending bool
	)
	err := s.engine.Query(func(b engine.Namespace) error {
		v, err := b.Sub([]byte(engine.DefaultNamespace)).
			GetEncrypted([]byte(compactPendingKey))
		pending = !isMissing(err)
		if err == nil {
			mark = v
		}
		return nil
	})
	if err != nil {
		return nil, false, fmt.Errorf("read compaction mark: %w", err)
	}
	return mark, pending, nil
}

// clearCompactMark removes [compactPendingKey] after a compaction, unless
// its value is no longer mark, as [Storage.compactMark] read it before the
// compaction: a later delete marked the database again, and its freed
// data may not have been compacted yet. A failure is only logged, since
// the next open then compacts again.
func (s *Storage) clearCompactMark(mark []byte) {
	err := s.engine.Command(func(b engine.Namespace) error {
		def := b.Sub([]byte(engine.DefaultNamespace))
		v, err := def.GetEncrypted([]byte(compactPendingKey))
		switch {
		case isMissing(err):
			return nil
		case err == nil && !bytes.Equal(v, mark),
			err != nil && mark != nil:
			return nil
		}
		return def.Delete([]byte(compactPendingKey))
	})
	if err != nil {
		slog.Warn(
			"could not clear the compaction mark; "+
				"the next open compacts the database again",
			slog.Any("error", err),
		)
	}
}

// compactIfPending compacts the database when [compactPendingKey] says
// it holds data in free pages that it must not keep. A compaction that
// fails, such as on a full disk or without the lock file, is logged and
// tried again on the next open.
func (s *Storage) compactIfPending() error {
	_, pending, err := s.compactMark()
	if err != nil || !pending {
		return err
	}
	if err := s.Compact(); err != nil {
		if errors.Is(err, ErrReopen) {
			return err
		}
		slog.Warn(
			"could not compact the database; deleted data and the "+
				"layout of an upgrade stay in free pages until an "+
				"open compacts it",
			slog.Any("error", err),
		)
	}
	return nil
}

// formatVersion returns the recorded version of the database layout.
func (s *Storage) formatVersion() (byte, error) {
	var v []byte
	err := s.engine.Query(func(b engine.Namespace) error {
		var err error
		v, err = b.Sub([]byte(engine.DefaultNamespace)).
			GetEncrypted([]byte(formatKey))
		return err
	})
	switch {
	case isMissing(err):
		return 0, nil
	case err != nil:
		return 0, fmt.Errorf("read format version: %w", err)
	case len(v) != 1:
		return 0, fmt.Errorf("format version is %d bytes", len(v))
	}
	return v[0], nil
}

// convertLegacyChats converts the chat entries of every session that are
// still under legacy keys with [convertLegacyChat], one session per
// transaction. It returns how many entries it converted or dropped.
func (s *Storage) convertLegacyChats() (int, error) {
	var names []string
	err := s.engine.Query(func(b engine.Namespace) error {
		names = b.Sub([]byte(engine.SessionsNamespace)).ListSubNamespaces()
		return nil
	})
	if err != nil {
		return 0, err
	}

	var changed int
	for _, name := range names {
		err := s.engine.Command(func(b engine.Namespace) error {
			session := b.Sub([]byte(engine.SessionsNamespace)).
				Sub([]byte(name))
			chat := session.Sub([]byte("chat"))
			if first := chat.FirstKey(); first == nil ||
				isChatIndexKey(first) {
				return nil
			}
			n, _, dropped, err := convertLegacyChat(chat)
			if err != nil {
				return err
			}
			changed += n + dropped
			meta := session.Sub([]byte("meta"))
			if count, ok := messageCount(meta); ok && dropped > 0 {
				return putMessageCount(meta, max(count-dropped, 0))
			}
			return nil
		})
		if err != nil {
			return 0, fmt.Errorf("session %q: %w", name, err)
		}
	}
	return changed, nil
}
