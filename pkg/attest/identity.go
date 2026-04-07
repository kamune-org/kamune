package attest

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Identity struct {
	Algorithm Algorithm
	PublicKey PublicKey
}

type identity struct {
	Algorithm Algorithm `json:"algorithm"`
	PublicKey []byte    `json:"public_key"`
}

func (i *Identity) UnmarshalJSON(b []byte) error {
	var id identity
	if err := json.Unmarshal(b, &id); err != nil {
		return err
	}

	pub, err := id.Algorithm.Identitfier().ParsePublicKey(id.PublicKey)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}

	*i = Identity{
		Algorithm: id.Algorithm,
		PublicKey: pub,
	}
	return nil
}

func (Identity) Parse(s string) (Identity, error) {
	var i Identity
	parts := strings.SplitN(s, ":", 2)
	if l := len(parts); l != 2 {
		return i, fmt.Errorf("expected two parts, got: %d", l)
	}
	var alg Algorithm
	if err := alg.UnmarshalText([]byte(parts[0])); err != nil {
		return i, fmt.Errorf("parse algorithm: %w", err)
	}
	pub, err := alg.Identitfier().ParsePublicKey([]byte(parts[1]))
	if err != nil {
		return i, fmt.Errorf("parse public key: %w", err)
	}

	return Identity{Algorithm: alg, PublicKey: pub}, nil
}
