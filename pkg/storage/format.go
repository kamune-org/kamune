package storage

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/kamune-org/kamune/internal/engine"
)

// formatKey, in the default namespace, holds the version of the layout the
// database is in, as one byte sealed under the data key. A database
// without it was written before versions were recorded, and is version 0.
const formatKey = "storage-format"

// storageFormat is the version of the layout this package writes. Each
// version adds to the one before it:
//   - 1: chat entries are keyed by index, and hold their receive time and
//     sender in their padded value (see [chatKeyPrefix])
const storageFormat = 1

// upgradeFormat brings the database up to [storageFormat] and records it.
// Each step can be run again on data it already converted, so a step that
// is interrupted, by a crash or an error, is completed on the next open.
// When a step changed anything, the database is compacted afterwards, so
// that the old layout does not stay in free pages.
func (s *Storage) upgradeFormat() error {
	version, err := s.formatVersion()
	if err != nil {
		return err
	}
	switch {
	case version == storageFormat:
		return nil
	case version > storageFormat:
		return fmt.Errorf(
			"%w: version %d, supported %d",
			ErrUnsupportedFormat, version, storageFormat,
		)
	}

	changed, err := s.convertLegacyChats()
	if err != nil {
		return fmt.Errorf("convert chat entries: %w", err)
	}
	err = s.engine.Command(func(b engine.Namespace) error {
		return b.Ensure([]byte(engine.DefaultNamespace)).PutEncrypted(
			[]byte(formatKey), []byte{storageFormat},
		)
	})
	if err != nil {
		return fmt.Errorf("record format version: %w", err)
	}
	if changed == 0 {
		return nil
	}

	slog.Info(
		"upgraded database format",
		slog.Int("from", int(version)),
		slog.Int("to", storageFormat),
	)
	if err := s.Compact(); err != nil {
		if errors.Is(err, ErrReopen) {
			return err
		}
		slog.Warn(
			"could not compact the database after upgrading it; "+
				"its old layout stays in free pages",
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
