package ratchet

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/kamune-org/kamune/pkg/exchange"
)

var (
	ErrInvalidState = errors.New("invalid ratchet state")
)

// State represents a serializable snapshot of the Ratchet's internal state.
// This allows persisting and restoring ratchet sessions.
type State struct {
	RootKey   []byte `json:"root_key"`
	SendCK    []byte `json:"send_ck"`
	RecvCK    []byte `json:"recv_ck"`
	OurDHPriv []byte `json:"our_dh_priv"`
	OurDHPub  []byte `json:"our_dh_pub"`
	TheirPub  []byte `json:"their_pub"`
	SendCount uint64 `json:"send_count"`
	RecvCount uint64 `json:"recv_count"`
}

// Save captures the current state of the ratchet into a serializable State object.
func (r *Ratchet) Save() (*State, error) {
	if r.ourDH == nil {
		return nil, errors.New("ratchet DH keypair is nil")
	}

	// Marshal the private key
	privBytes := r.ourDH.MarshalPrivateKey()

	state := &State{
		RootKey:   copyBytes(r.rootKey),
		SendCK:    copyBytes(r.sendCK),
		RecvCK:    copyBytes(r.recvCK),
		OurDHPriv: privBytes,
		OurDHPub:  r.ourDH.MarshalPublicKey(),
		TheirPub:  copyBytes(r.theirPub),
		SendCount: r.sendCount,
		RecvCount: r.recvCount,
	}

	return state, nil
}

// Restore reconstructs a Ratchet from a previously saved State.
func Restore(state *State) (*Ratchet, error) {
	if state == nil {
		return nil, ErrInvalidState
	}

	// Validate essential fields
	if len(state.RootKey) == 0 {
		return nil, fmt.Errorf("%w: missing root key", ErrInvalidState)
	}
	if len(state.OurDHPriv) == 0 {
		return nil, fmt.Errorf("%w: missing our DH private key", ErrInvalidState)
	}
	if len(state.OurDHPub) == 0 {
		return nil, fmt.Errorf("%w: missing our DH public key", ErrInvalidState)
	}

	// Reconstruct the ECDH keypair
	dh, err := exchange.RestoreECDH(state.OurDHPriv, state.OurDHPub)
	if err != nil {
		return nil, fmt.Errorf("restoring ECDH keypair: %w", err)
	}

	r := &Ratchet{
		rootKey:   copyBytes(state.RootKey),
		sendCK:    copyBytes(state.SendCK),
		recvCK:    copyBytes(state.RecvCK),
		ourDH:     dh,
		theirPub:  copyBytes(state.TheirPub),
		sendCount: state.SendCount,
		recvCount: state.RecvCount,
	}

	return r, nil
}

// MarshalJSON serializes the State to JSON format.
func (s *State) MarshalJSON() ([]byte, error) {
	type Alias State
	return json.Marshal(&struct {
		*Alias
	}{
		Alias: (*Alias)(s),
	})
}

// UnmarshalJSON deserializes the State from JSON format.
func (s *State) UnmarshalJSON(data []byte) error {
	type Alias State
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(s),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	return nil
}

// Serialize encodes the State to JSON bytes.
func (s *State) Serialize() ([]byte, error) {
	return json.Marshal(s)
}

// Deserialize decodes a State from JSON bytes.
func Deserialize(data []byte) (*State, error) {
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("deserializing state: %w", err)
	}
	return &state, nil
}

// Clone creates a deep copy of the State.
func (s *State) Clone() *State {
	if s == nil {
		return nil
	}
	return &State{
		RootKey:   copyBytes(s.RootKey),
		SendCK:    copyBytes(s.SendCK),
		RecvCK:    copyBytes(s.RecvCK),
		OurDHPriv: copyBytes(s.OurDHPriv),
		OurDHPub:  copyBytes(s.OurDHPub),
		TheirPub:  copyBytes(s.TheirPub),
		SendCount: s.SendCount,
		RecvCount: s.RecvCount,
	}
}

// copyBytes creates a copy of a byte slice, returning nil if the input is nil.
func copyBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	result := make([]byte, len(b))
	copy(result, b)
	return result
}
