package relayleg

import (
	"crypto/rand"
	"errors"
	"fmt"
)

// PSK is a generated relay access key.
type PSK [32]byte

// String returns the canonical text form: psk1- plus lowercase
// base32 of the 32 bytes, with no padding.
func (p PSK) String() string {
	return pskPrefix + encodeRaw(p[:])
}

// ParsePSK parses an access key. The text rules match ParsePublicKey,
// with the prefix psk1-. The all-zero key is rejected.
func ParsePSK(s string) (PSK, error) {
	raw, err := parseFixedKey(s, pskPrefix, ErrInvalidPSK)
	if err != nil {
		return PSK{}, err
	}
	return PSK(raw), nil
}

// GeneratePSK returns a new access key from crypto/rand.
// It does not return the all-zero key.
func GeneratePSK() (PSK, error) {
	var p PSK
	if _, err := rand.Read(p[:]); err != nil {
		return PSK{}, fmt.Errorf("generate PSK: %w", err)
	}
	if p == (PSK{}) {
		// A zero PSK has the same early secret as no PSK.
		// crypto/rand does not produce 256 zero bits; refuse
		// it if it ever does.
		return PSK{}, errors.New("generate PSK: zero")
	}
	return p, nil
}
