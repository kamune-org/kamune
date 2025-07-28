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

func (e *ECDH) Exchange(remote []byte) ([]byte, error) {
	key, err := x509.ParsePKIXPublicKey(remote)
	if err != nil {
		return nil, fmt.Errorf("parsing key: %w", err)
	}
	pub, ok := key.(*ecdh.PublicKey)
	if !ok {
		return nil, ErrInvalidKey
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
