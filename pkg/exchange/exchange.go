// Package exchange implements key exchange and encrypted channel primitives
// for the kamune protocol. It provides HPKE-based encrypted channels
// (MLKEM768-X25519 + HKDF-SHA512 + ChaCha20-Poly1305) and ML-KEM-768
// post-quantum encapsulation for the handshake key agreement.
package exchange

import (
	"errors"
)

var (
	ErrInvalidKey = errors.New("invalid key type")
)
