package storage

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/kamune-org/kamune/internal/store"
)

const (
	resumptionTokenSize = 32
)

// SessionRecord holds metadata for a session stored under sessions/<id>.
type SessionRecord struct {
	EstablishedAt time.Time
	Peer          *Peer
	Token         []byte
}

var (
	ErrSessionNotFound = errors.New("session not found")
	ErrTokenNotFound   = errors.New("token not found")

	resumptionTokensKey = []byte("resumption_tokens")
	establishedAtKey    = []byte("established_at")
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
		err = meta.PutEncrypted([]byte("peer"), peer.PublicKey)
		if err != nil {
			return fmt.Errorf("store peer key: %w", err)
		}

		// Store establishment timestamp.
		var tsBuf [8]byte
		binary.BigEndian.PutUint64(tsBuf[:], uint64(time.Now().UnixNano()))
		err = meta.PutEncrypted(establishedAtKey, tsBuf[:])
		if err != nil {
			return fmt.Errorf("store established_at: %w", err)
		}

		// Pre-create the chat sub-bucket so GetChatHistory works without
		// attempting to create it inside a read-only Query.
		sessionChat(b, sessionID)

		return nil
	})
	if err != nil {
		return fmt.Errorf("create session %s: %w", sessionID, err)
	}
	return nil
}

// StoreResumptionTokens stores the resumption token set for a session.
// Tokens are stored as a serialized binary blob: uint32 count followed by
// N * 32-byte (resumptionTokenSize) tokens.
func (s *Storage) StoreResumptionTokens(sessionID string, tokens [][]byte) error {
	err := s.store.Command(func(b *store.Bucket) error {
		meta := sessionMeta(b, sessionID)
		data := serializeTokens(tokens)
		return meta.PutEncrypted(resumptionTokensKey, data)
	})
	if err != nil {
		return fmt.Errorf("store resumption tokens for %s: %w", sessionID, err)
	}
	return nil
}

func (s *Storage) GetSession(
	sessionID string,
) (*SessionRecord, error) {
	record := &SessionRecord{}
	err := s.store.Command(func(b *store.Bucket) error {
		meta := sessionMeta(b, sessionID)

		peerPublicKey, err := meta.GetEncrypted([]byte("peer"))
		if err != nil {
			return fmt.Errorf("get peer key: %w", err)
		}
		peer, err := s.findPeer(b, peerKey(peerPublicKey))
		if err != nil {
			return fmt.Errorf("find peer: %w", err)
		}
		record.Peer = peer

		// Check if the session exists by looking for established_at.
		tsBytes, err := meta.GetEncrypted(establishedAtKey)
		if err != nil {
			return fmt.Errorf("get established_at: %w", err)
		}
		if len(tsBytes) == 8 {
			record.EstablishedAt = time.Unix(
				0, int64(binary.BigEndian.Uint64(tsBytes)),
			)
		}

		data, err := meta.GetEncrypted(resumptionTokensKey)
		if err != nil {
			if errors.Is(err, store.ErrMissingItem) {
				return nil
			}
			return err
		}
		tokens := deserializeTokens(data)
		if len(tokens) == 0 {
			return nil
		}
		token := tokens[0]
		tokens = tokens[1:]
		err = meta.PutEncrypted(resumptionTokensKey, serializeTokens(tokens))
		if err != nil {
			return fmt.Errorf("store resumption tokens: %w", err)
		}
		record.Token = token

		return nil
	})
	if err != nil {
		if errors.Is(err, store.ErrMissingItem) ||
			errors.Is(err, store.ErrMissingBucket) {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("get session %s: %w", sessionID, err)
	}
	return record, nil
}

func (s *Storage) MarkTokenUsed(
	sessionID string, token []byte,
) (*SessionRecord, error) {
	record := &SessionRecord{Token: token}
	err := s.store.Command(func(b *store.Bucket) error {
		meta := sessionMeta(b, sessionID)

		peerPublicKey, err := meta.GetEncrypted([]byte("peer"))
		if err != nil {
			return fmt.Errorf("get peer key: %w", err)
		}
		peer, err := s.findPeer(b, peerKey(peerPublicKey))
		if err != nil {
			return fmt.Errorf("find peer: %w", err)
		}
		record.Peer = peer

		// Check if the session exists by looking for established_at.
		tsBytes, err := meta.GetEncrypted(establishedAtKey)
		if err != nil {
			return fmt.Errorf("get established_at: %w", err)
		}
		if len(tsBytes) == 8 {
			record.EstablishedAt = time.Unix(
				0, int64(binary.BigEndian.Uint64(tsBytes)),
			)
		}

		data, err := meta.GetEncrypted(resumptionTokensKey)
		if err != nil {
			return fmt.Errorf("get resumption tokens: %w", err)
		}
		tokens := deserializeTokens(data)
		for i, t := range tokens {
			if subtle.ConstantTimeCompare(t, token) == 1 {
				// Remove by swapping with last and truncating.
				tokens[i] = tokens[len(tokens)-1]
				tokens = tokens[:len(tokens)-1]
				err = meta.PutEncrypted(
					resumptionTokensKey, serializeTokens(tokens),
				)
				if err != nil {
					return fmt.Errorf("put resumption tokens: %w", err)
				}
				return nil
			}
		}

		return ErrTokenNotFound
	})

	if err != nil {
		return nil, fmt.Errorf("mark token used for %s: %w", sessionID, err)
	}
	return record, nil
}

// serializeTokens encodes a token set as: uint32(count) || token_0 || ... || token_N-1.
func serializeTokens(tokens [][]byte) []byte {
	count := uint32(len(tokens))
	data := make([]byte, 4+len(tokens)*resumptionTokenSize)
	binary.BigEndian.PutUint32(data[:4], count)
	for i, t := range tokens {
		copy(data[4+i*resumptionTokenSize:], t)
	}
	return data
}

// deserializeTokens decodes a token set from the serialized format.
func deserializeTokens(data []byte) [][]byte {
	if len(data) < 4 {
		return nil
	}
	count := int(binary.BigEndian.Uint32(data[0:4]))
	if len(data) < 4+count*resumptionTokenSize {
		return nil
	}
	tokens := make([][]byte, count)
	for i := range tokens {
		off := 4 + i*resumptionTokenSize
		tokens[i] = data[off : off+resumptionTokenSize]
	}
	return tokens
}
