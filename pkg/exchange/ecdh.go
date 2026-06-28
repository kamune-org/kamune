package exchange

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
)

// ECDH wraps an X25519 key pair for Diffie-Hellman key exchange.
type ECDH struct {
	publicKey  *ecdh.PublicKey
	privateKey *ecdh.PrivateKey
}

// MarshalPublicKey returns the raw 32-byte X25519 public key.
func (e *ECDH) MarshalPublicKey() []byte {
	return e.publicKey.Bytes()
}

// Exchange performs an ECDH exchange with the given remote public key.
func (e *ECDH) Exchange(remote []byte) ([]byte, error) {
	pub, err := ecdh.X25519().NewPublicKey(remote)
	if err != nil {
		return nil, fmt.Errorf("parsing key: %w", err)
	}
	secret, err := e.privateKey.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("performing ecdh exchange: %w", err)
	}

	return secret, nil
}

// NewECDH generates a new X25519 key pair.
func NewECDH() (*ECDH, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &ECDH{privateKey: key, publicKey: key.PublicKey()}, nil
}
