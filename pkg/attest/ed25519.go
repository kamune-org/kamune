package attest

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"

	"golang.org/x/crypto/ed25519"
)

type Ed25519 struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

func (e Ed25519) PublicKey() PublicKey {
	return &Ed25519PublicKey{e.publicKey}
}

func (e Ed25519) Sign(msg []byte) ([]byte, error) {
	return ed25519.Sign(e.privateKey, msg), nil
}

func (e Ed25519) Save() ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(e.privateKey)
}

func (Ed25519) Verify(remote PublicKey, msg, sig []byte) bool {
	p, ok := remote.(*Ed25519PublicKey)
	if !ok {
		return false
	}
	return ed25519.Verify(p.key, msg, sig)
}

func (Ed25519) ParsePublicKey(key []byte) (PublicKey, error) {
	pk, err := x509.ParsePKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	edPub, ok := pk.(ed25519.PublicKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	return &Ed25519PublicKey{key: edPub}, nil
}

func (Ed25519) String() string {
	return "ed25519"
}

type Ed25519PublicKey struct {
	key ed25519.PublicKey
}

func (p Ed25519PublicKey) Marshal() []byte {
	b, err := x509.MarshalPKIXPublicKey(p.key)
	if err != nil {
		panic(fmt.Errorf("marshalling public key: %w", err))
	}
	return b
}

func (p Ed25519PublicKey) Equal(x PublicKey) bool {
	pk, ok := x.(*Ed25519PublicKey)
	if !ok {
		p.key.Equal(x)
	}
	return p.key.Equal(pk.key)
}

func newEd25519DSA() (*Ed25519, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Ed25519{privateKey: private, publicKey: public}, nil
}

func loadEd25519(data []byte) (*Ed25519, error) {
	key, err := x509.ParsePKCS8PrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("parsing key: %w", err)
	}
	private, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	return &Ed25519{
		privateKey: private,
		publicKey:  private.Public().(ed25519.PublicKey),
	}, nil
}
