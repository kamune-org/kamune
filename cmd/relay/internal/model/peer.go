package model

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/kamune-org/kamune/pkg/attest"

	"github.com/kamune-org/kamune/cmd/relay/pkg/span"
)

type Peer struct {
	ID           PeerID        `json:"id,omitzero"`
	Address      []string      `json:"address"`
	PublicKey    PublicKey     `json:"public_key"`
	RegisteredAt time.Time     `json:"registered_at"`
	ExpiresIn    span.Duration `json:"expires_in,omitzero"`
}

type PeerID uuid.UUID

func NewPeerID() PeerID {
	return PeerID(uuid.New())
}

func EmptyPeerID() PeerID {
	return PeerID(uuid.Nil)
}

func (p PeerID) String() string {
	return uuid.UUID(p).String()
}

func (p PeerID) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.String())
}

func (p *PeerID) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return err
	}
	*p = PeerID(id)
	return nil
}

func (p PeerID) MarshalBinary() ([]byte, error) {
	return uuid.UUID(p).MarshalBinary()
}

func (p *PeerID) UnmarshalBinary(data []byte) error {
	var id uuid.UUID
	err := (&id).UnmarshalBinary(data)
	if err != nil {
		return err
	}
	*p = PeerID(id)
	return nil
}

type PublicKey string

func (pk PublicKey) String() string {
	return string(pk)
}

func (pk *PublicKey) UnmarshalText(b []byte) error {
	if len(b) == 0 {
		return errors.New("empty public key")
	}

	key := make([]byte, base64.RawURLEncoding.DecodedLen(len(b)))
	n, err := base64.RawStdEncoding.Decode(key, b)
	if err != nil {
		return err
	}
	key = key[:n]
	if ok := attest.IsValidPublicKey(key); !ok {
		return errors.New("invalid key")
	}

	*pk = PublicKey(key)
	return nil
}

func ParsePublicKey(s string) (PublicKey, error) {
	var pk PublicKey
	if err := pk.UnmarshalText([]byte(s)); err != nil {
		return "", err
	}
	return pk, nil
}
