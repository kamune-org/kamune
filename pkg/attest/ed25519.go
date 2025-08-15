package attest

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"

	"golang.org/x/crypto/ed25519"
)

type ed25519DSA struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

func newEd25519DSA() (*ed25519DSA, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &ed25519DSA{privateKey: private, publicKey: public}, nil
}

func (e *ed25519DSA) PublicKey() PublicKey {
	return &ed25519PublicKey{e.publicKey}
}

func (e *ed25519DSA) Sign(msg []byte) ([]byte, error) {
	return ed25519.Sign(e.privateKey, msg), nil
}

func (e *ed25519DSA) Save() ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(e.privateKey)
}

type ed25519PublicKey struct {
	key ed25519.PublicKey
}

func (p *ed25519PublicKey) Marshal() []byte {
	b, err := x509.MarshalPKIXPublicKey(p.key)
	if err != nil {
		panic(fmt.Errorf("marshalling public key: %w", err))
	}
	return b
}

func (p *ed25519PublicKey) Equal(x PublicKey) bool {
	pk, ok := x.(*ed25519PublicKey)
	if !ok {
		p.key.Equal(x)
	}
	return p.key.Equal(pk.key)
}

func loadEd25519(data []byte) (*ed25519DSA, error) {
	key, err := x509.ParsePKCS8PrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("parsing key: %w", err)
	}
	private, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	return &ed25519DSA{
		privateKey: private,
		publicKey:  private.Public().(ed25519.PublicKey),
	}, nil
}
