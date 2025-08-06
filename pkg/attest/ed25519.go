package attest

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/ed25519"
)

type Ed25519 struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

func NewEd25519() (Attest, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Ed25519{privateKey: private, publicKey: public}, nil
}

func (e *Ed25519) PublicKey() PublicKey {
	return &ed25519PublicKey{e.publicKey}
}

func (e *Ed25519) Sign(msg, _ []byte) ([]byte, error) {
	return ed25519.Sign(e.privateKey, msg), nil
}

func (e *Ed25519) Save(path string) error {
	private, err := x509.MarshalPKCS8PrivateKey(e.privateKey)
	if err != nil {
		return fmt.Errorf("marshalling private key: %w", err)
	}
	public, err := x509.MarshalPKIXPublicKey(e.publicKey)
	if err != nil {
		return fmt.Errorf("marshalling public key: %w", err)
	}
	return save(private, public, path)
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

func (p *ed25519PublicKey) Base64Encoding() string {
	return base64.RawStdEncoding.EncodeToString(p.Marshal())
}

func (p *ed25519PublicKey) Equal(x PublicKey) bool {
	pk, ok := x.(*ed25519PublicKey)
	if !ok {
		p.key.Equal(x)
	}
	return p.key.Equal(pk.key)
}
