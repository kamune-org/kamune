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
	// ErrFrameTooLarge is returned by a Channel write when the sealed frame
	// would exceed the limit reported by the underlying FrameLimiter. The
	// frame is rejected before encryption, so the Channel stays usable.
	ErrFrameTooLarge = errors.New("sealed frame exceeds the frame limit")
	// ErrChannelBroken is returned by every Channel write after a write of a
	// sealed frame failed. The failed frame consumed an HPKE sequence number
	// the peer never saw, so no later frame could be opened by the peer.
	ErrChannelBroken = errors.New("channel broken by a failed write")
)
