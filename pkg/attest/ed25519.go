package attest

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/ed25519"
)

type Attest struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

func New() (*Attest, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Attest{privateKey: private, publicKey: public}, nil
}

func (e *Attest) PublicKey() *PublicKey {
	return &PublicKey{e.publicKey}
}

func (e *Attest) MarshalPublicKey() []byte {
	b, err := x509.MarshalPKIXPublicKey(e.publicKey)
	if err != nil {
		panic(fmt.Errorf("marshalling public key: %w", err))
	}
	return b
}

func (e *Attest) Sign(msg []byte) ([]byte, error) {
	return ed25519.Sign(e.privateKey, msg), nil
}

func (e *Attest) Save(path string) error {
	private, err := x509.MarshalPKCS8PrivateKey(e.privateKey)
	if err != nil {
		return fmt.Errorf("marshalling key: %w", err)
	}
	err = saveKey(private, privateKeyType, path)
	if err != nil {
		return fmt.Errorf("saving private key: %w", err)
	}
	err = saveKey(e.MarshalPublicKey(), publicKeyType, path+".pub")
	if err != nil {
		return fmt.Errorf("saving public key: %w", err)
	}

	return nil
}

func Verify(r *PublicKey, msg, sig []byte) bool {
	return ed25519.Verify(r.key, msg, sig)
}

type PublicKey struct {
	key ed25519.PublicKey
}

func (p *PublicKey) Marshal() []byte {
	b, err := x509.MarshalPKIXPublicKey(p.key)
	if err != nil {
		panic(fmt.Errorf("marshalling public key: %w", err))
	}
	return b
}

func (p *PublicKey) Equal(x crypto.PublicKey) bool {
	pk, ok := x.(*PublicKey)
	if !ok {
		p.key.Equal(x)
	}
	return p.key.Equal(pk.key)
}

func ParsePublicKey(remote []byte) (*PublicKey, error) {
	pk, err := x509.ParsePKIXPublicKey(remote)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	pub, ok := pk.(ed25519.PublicKey)
	if !ok {
		return nil, ErrInvalidKey
	}

	return &PublicKey{key: pub}, nil
}

func LoadFromDisk(path string) (*Attest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrMissingFile
		}
		return nil, fmt.Errorf("reading file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrMissingPEM
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing key: %w", err)
	}
	private, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	public, ok := private.Public().(ed25519.PublicKey)
	if !ok {
		panic("type assertion: public key is not of type ed25519")
	}

	return &Attest{privateKey: private, publicKey: public}, nil
}
