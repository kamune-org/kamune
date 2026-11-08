package relayleg

import (
	"crypto/ecdh"
	"crypto/sha256"
)

// keyHintLabel is the domain string mixed into KeyHint.
const keyHintLabel = "kamune relayleg v2 key hint"

// PublicKey is a relay static X25519 public key.
type PublicKey [32]byte

// String returns the canonical text form: rk1- plus lowercase
// base32 of the 32 bytes, with no padding.
func (k PublicKey) String() string {
	return relayPrefix + encodeRaw(k[:])
}

// Display returns the text form with the base32 in groups of four,
// for a person to compare.
func (k PublicKey) Display() string {
	return relayPrefix + group4(encodeRaw(k[:]))
}

// ParsePublicKey parses a relay public key. Surrounding space is
// trimmed. Upper and lower case are accepted. Dashes and spaces inside
// the base32 are ignored. Any other prefix, a non-base32 character, a
// decoded length other than 32, non-zero unused bits in the last
// character, and the all-zero key are rejected.
func ParsePublicKey(s string) (PublicKey, error) {
	raw, err := parseFixedKey(s, relayPrefix, ErrInvalidRelayKey)
	if err != nil {
		return PublicKey{}, err
	}
	return PublicKey(raw), nil
}

// ECDH returns k as an X25519 public key.
func (k PublicKey) ECDH() (*ecdh.PublicKey, error) {
	return ecdh.X25519().NewPublicKey(k[:])
}

// KeyHint returns the first 4 bytes of
// SHA-256("kamune relayleg v2 key hint" || k).
func KeyHint(k PublicKey) [4]byte {
	msg := append([]byte(keyHintLabel), k[:]...)
	sum := sha256.Sum256(msg)
	var out [4]byte
	copy(out[:], sum[:4])
	return out
}
