package model

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/relay/pkg/span"
)

type Peer struct {
	ID           PeerID           `json:"id,omitzero"`
	Address      []string         `json:"address"`
	Identity     attest.Algorithm `json:"identity"`
	RegisteredAt time.Time        `json:"registered_at"`
	ExpiresIn    span.Duration    `json:"expires_in,omitzero"`
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
