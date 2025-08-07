package attest

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
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

func (e *ed25519DSA) Save(path string) error {
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

func loadEd25519(path string) (*ed25519DSA, error) {
	data, err := loadFromDisk(path)
	if err != nil {
		return nil, fmt.Errorf("load from disk: %w", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("parsing key: %w", err)
	}
	edPrivate, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	return &ed25519DSA{
		privateKey: edPrivate,
		publicKey:  edPrivate.Public().(ed25519.PublicKey),
	}, nil
}
