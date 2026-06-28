package relayconn

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
)

// TokenSize is the length in bytes of session tokens used by the relay
// wire protocol. It is also the truncation length applied to the
// SHA-256 digest of the two peers' public keys.
const TokenSize = 16

// ErrInvalidKeySize is returned by TokenFromKeys when either input
// public key is not exactly ed25519.PublicKeySize bytes.
var ErrInvalidKeySize = errors.New(
	"public key must be ed25519.PublicKeySize bytes",
)

// TokenFromKeys returns a 16-byte session token derived from two
// peers' public keys. The token is order-independent: TokenFromKeys(A, B)
// == TokenFromKeys(B, A). Both peers must use ed25519 public keys of
// the standard 32-byte size to compute the same token.
func TokenFromKeys(a, b ed25519.PublicKey) ([]byte, error) {
	if len(a) != ed25519.PublicKeySize || len(b) != ed25519.PublicKeySize {
		return nil, ErrInvalidKeySize
	}
	lo, hi := a, b
	if bytes.Compare(a, b) > 0 {
		lo, hi = b, a
	}
	h := sha256.New()
	h.Write(lo)
	h.Write(hi)
	sum := h.Sum(nil)
	out := make([]byte, TokenSize)
	copy(out, sum[:TokenSize])
	return out, nil
}
