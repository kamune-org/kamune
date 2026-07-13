package storage

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/kamune-org/kamune/internal/store"
)

// ElemSize is the fixed size in bytes of each element in a packed list.
const ElemSize = 32

// Meta is a key-value pair stored in a session's metadata bucket.
// It carries both the key and the encoded value, coupling them together to
// prevent mismatches.
type Meta struct {
	key, value []byte
}

// NewBytesMeta creates a Meta carrying raw bytes under the given key.
func NewBytesMeta(key string, value []byte) Meta {
	return Meta{key: []byte(key), value: value}
}

// NewByteSlicesMeta creates a Meta carrying packed byte slices
// (count prefix + fixed-size elements).
func NewByteSlicesMeta(key string, slices [][]byte) Meta {
	return Meta{
		key:   []byte(key),
		value: serializeList(slices),
	}
}

func (m Meta) Key() string   { return string(m.key) }
func (m Meta) Value() []byte { return m.value }

// Exported metadata key constants for session meta buckets.
const (
	PeerKey             = "peer"
	EstablishedAtKey    = "established_at"
	ResumptionTokensKey = "resumption_tokens"
	RelayTokensKey      = "relay_tokens"
)

var (
	ErrSessionNotFound = errors.New("session not found")
	ErrNotFound        = errors.New("not found")
)

// CreateSession creates a new session record under sessions/<id>/meta/ with
// peer key, peer name, and establishment timestamp.
func (s *Storage) CreateSession(sessionID string, publicKey []byte) error {
	err := s.store.Command(func(b *store.Bucket) error {
		peer, err := s.findPeer(b, peerKey(publicKey))
		if err != nil {
			return fmt.Errorf("find peer: %w", err)
		}

		meta := sessionMeta(b, sessionID)
		err = meta.PutEncrypted([]byte(PeerKey), peer.PublicKey)
		if err != nil {
			return fmt.Errorf("store peer key: %w", err)
		}

		// Store establishment timestamp.
		var tsBuf [8]byte
		binary.BigEndian.PutUint64(tsBuf[:], uint64(s.clock.Now().UnixNano()))
		err = meta.PutEncrypted([]byte(EstablishedAtKey), tsBuf[:])
		if err != nil {
			return fmt.Errorf("store established_at: %w", err)
		}

		// Pre-create the chat sub-bucket so GetChatHistory works without
		// attempting to create it inside a read-only Query.
		_ = sessionChat(b, sessionID)

		return nil
	})
	if err != nil {
		return fmt.Errorf("create session %s: %w", sessionID, err)
	}
	return nil
}

// GetMeta reads a single key from a session's meta bucket. Returns a Meta with
// nil Value when the key does not exist.
func (s *Storage) GetMeta(sessionID, key string) (Meta, error) {
	var val []byte
	err := s.store.Query(func(b *store.Bucket) error {
		meta := sessionMeta(b, sessionID)
		data, err := meta.GetEncrypted([]byte(key))
		if err != nil {
			return err
		}
		val = data
		return nil
	})
	if err != nil {
		if isMissing(err) {
			return Meta{}, nil
		}
		return Meta{}, fmt.Errorf("get session meta %s/%s: %w", sessionID, key, err)
	}
	return NewBytesMeta(key, val), nil
}

// SetMeta writes a Meta's key-value pair into a session's meta bucket.
func (s *Storage) SetMeta(sessionID string, m Meta) error {
	err := s.store.Command(func(b *store.Bucket) error {
		meta := sessionMeta(b, sessionID)
		return meta.PutEncrypted(m.key, m.value)
	})
	if err != nil {
		return fmt.Errorf("set session meta %s/%s: %w", sessionID, m.Key(), err)
	}
	return nil
}

// DeleteMeta removes a key from a session's meta bucket.
func (s *Storage) DeleteMeta(sessionID, key string) error {
	err := s.store.Command(func(b *store.Bucket) error {
		meta := sessionMeta(b, sessionID)
		return meta.Delete([]byte(key))
	})
	if err != nil {
		return fmt.Errorf("delete session meta %s/%s: %w", sessionID, key, err)
	}
	return nil
}

// GetPeer returns the peer associated with a session.
func (s *Storage) GetPeer(sessionID string) (*Peer, error) {
	m, err := s.GetMeta(sessionID, PeerKey)
	if err != nil {
		return nil, err
	}
	if m.Value() == nil {
		return nil, ErrSessionNotFound
	}
	var peer *Peer
	err = s.store.Query(func(b *store.Bucket) error {
		p, findErr := s.findPeer(b, peerKey(m.Value()))
		if findErr != nil {
			return findErr
		}
		peer = p
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("find peer for session %s: %w", sessionID, err)
	}
	return peer, nil
}

// GetEstablishedAt returns the establishment timestamp of a session.
func (s *Storage) GetEstablishedAt(sessionID string) (time.Time, error) {
	m, err := s.GetMeta(sessionID, EstablishedAtKey)
	if err != nil {
		return time.Time{}, err
	}
	if len(m.Value()) < 8 {
		return time.Time{}, ErrSessionNotFound
	}
	return time.Unix(0, int64(binary.BigEndian.Uint64(m.Value()[:8]))), nil
}

// PopList removes and returns the first entry from the packed list stored under
// the given key. Returns ErrNotFound when the list is empty or missing.
func (s *Storage) PopList(sessionID, key string) ([]byte, error) {
	var entry []byte
	err := s.store.Command(func(b *store.Bucket) error {
		meta := sessionMeta(b, sessionID)
		data, err := meta.GetEncrypted([]byte(key))
		if err != nil {
			return err
		}
		list, err := deserializeList(data)
		if err != nil {
			return err
		}
		if len(list) == 0 {
			return ErrNotFound
		}
		entry = list[0]
		list = list[1:]
		return meta.PutEncrypted([]byte(key), serializeList(list))
	})
	if err != nil {
		if isMissing(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("pop from %s/%s: %w", sessionID, key, err)
	}
	return entry, nil
}

// RemoveListItem removes a specific entry from the packed list stored under the
// given key. Returns ErrNotFound when the entry is not present.
func (s *Storage) RemoveListItem(sessionID, key string, entry []byte) error {
	err := s.store.Command(func(b *store.Bucket) error {
		meta := sessionMeta(b, sessionID)
		data, err := meta.GetEncrypted([]byte(key))
		if err != nil {
			return err
		}
		list, err := deserializeList(data)
		if err != nil {
			return err
		}
		for i, item := range list {
			if subtle.ConstantTimeCompare(item, entry) == 1 {
				// Remove by swapping with last and truncating.
				list[i] = list[len(list)-1]
				list = list[:len(list)-1]
				return meta.PutEncrypted([]byte(key), serializeList(list))
			}
		}
		return ErrNotFound
	})
	if err != nil {
		if isMissing(err) {
			return ErrNotFound
		}
		return fmt.Errorf("remove from %s/%s: %w", sessionID, key, err)
	}
	return nil
}

// serializeList encodes a list as: uint32(count) || elem_0 || ... || elem_N-1.
func serializeList(list [][]byte) []byte {
	count := uint32(len(list))
	data := make([]byte, 4+len(list)*ElemSize)
	binary.BigEndian.PutUint32(data[:4], count)
	for i, item := range list {
		copy(data[4+i*ElemSize:], item)
	}
	return data
}

// deserializeList decodes a list from the serialized format.
// Returns nil, nil when data is too short to contain a count prefix (<4 bytes).
// Returns nil, ErrNotFound when the data has a count prefix but the length
// doesn't match the expected packed format.
func deserializeList(data []byte) ([][]byte, error) {
	if len(data) < 4 {
		return nil, nil
	}
	count := int(binary.BigEndian.Uint32(data[0:4]))
	if 4+count*ElemSize != len(data) {
		return nil, ErrNotFound
	}
	list := make([][]byte, count)
	for i := range list {
		off := 4 + i*ElemSize
		list[i] = data[off : off+ElemSize]
	}
	return list, nil
}

// isMissing reports whether err indicates a missing bucket or item in the
// underlying store.
func isMissing(err error) bool {
	return errors.Is(err, store.ErrMissingItem) ||
		errors.Is(err, store.ErrMissingBucket)
}
