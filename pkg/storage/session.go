package storage

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/kamune-org/kamune/internal/store"
)

// SessionRecord holds metadata for a session stored under sessions/<id>.
type SessionRecord struct {
	ID            string
	PeerKey       []byte
	PeerName      string
	EstablishedAt time.Time
}

var (
	ErrSessionNotFound = errors.New("session not found")
)

// CreateSession creates a new session record under sessions/<id>/meta/ with
// peer key, peer name, and establishment timestamp.
func (s *Storage) CreateSession(
	sessionID string, peerKey []byte, peerName string,
) error {
	err := s.store.Command(func(b *store.Bucket) error {
		meta := sessionMeta(b, sessionID)

		// Store peer key.
		if len(peerKey) > 0 {
			err := meta.PutEncrypted([]byte("peer_key"), peerKey)
			if err != nil {
				return fmt.Errorf("store peer key: %w", err)
			}
		}

		// Store peer name.
		if peerName != "" {
			err := meta.PutEncrypted([]byte("peer_name"), []byte(peerName))
			if err != nil {
				return fmt.Errorf("store peer name: %w", err)
			}
		}

		// Store establishment timestamp.
		var tsBuf [8]byte
		binary.BigEndian.PutUint64(tsBuf[:], uint64(time.Now().UnixNano()))
		err := meta.PutEncrypted([]byte("established_at"), tsBuf[:])
		if err != nil {
			return fmt.Errorf("store established_at: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("create session %s: %w", sessionID, err)
	}
	return nil
}

// GetSession retrieves session metadata from sessions/<id>/meta/.
// Returns ErrSessionNotFound if the session does not exist.
func (s *Storage) GetSession(sessionID string) (*SessionRecord, error) {
	var record SessionRecord
	record.ID = sessionID

	err := s.store.Query(func(b *store.Bucket) error {
		meta := sessionMeta(b, sessionID)

		// Check if the session exists by looking for established_at.
		tsBytes, err := meta.GetEncrypted([]byte("established_at"))
		if err != nil {
			return err
		}
		if len(tsBytes) == 8 {
			record.EstablishedAt = time.Unix(
				0, int64(binary.BigEndian.Uint64(tsBytes)),
			)
		}

		// Peer key (may be empty).
		pk, err := meta.GetEncrypted([]byte("peer_key"))
		if err != nil && !errors.Is(err, store.ErrMissingItem) {
			return err
		}
		record.PeerKey = pk

		// Peer name.
		pn, err := meta.GetEncrypted([]byte("peer_name"))
		if err != nil && !errors.Is(err, store.ErrMissingItem) {
			return err
		}
		record.PeerName = string(pn)

		return nil
	})
	if err != nil {
		if errors.Is(err, store.ErrMissingItem) ||
			errors.Is(err, store.ErrMissingBucket) {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("get session %s: %w", sessionID, err)
	}
	return &record, nil
}
