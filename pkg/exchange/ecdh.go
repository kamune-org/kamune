package exchange

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"fmt"
)

type ECDH struct {
	PublicKey  *ecdh.PublicKey
	privateKey *ecdh.PrivateKey
}

func (e *ECDH) MarshalPublicKey() []byte {
	b, err := x509.MarshalPKIXPublicKey(e.PublicKey)
	if err != nil {
		panic(fmt.Errorf("marshalling public key: %w", err))
	}
	return b
}

func (e *ECDH) MarshalPrivateKey() []byte {
	return e.privateKey.Bytes()
}

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

func NewECDH() (*ECDH, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &ECDH{privateKey: key, PublicKey: key.PublicKey()}, nil
}

// RestoreECDH reconstructs an ECDH key pair from serialized private and public
// key bytes.
func RestoreECDH(privBytes, pubBytes []byte) (*ECDH, error) {
	// Restore the private key
	privKey, err := ecdh.X25519().NewPrivateKey(privBytes)
	if err != nil {
		return nil, fmt.Errorf("restoring private key: %w", err)
	}

	// Parse the public key
	pubKey, err := ecdh.X25519().NewPublicKey(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}

	return &ECDH{
		privateKey: privKey,
		PublicKey:  pubKey,
	}, nil
}
