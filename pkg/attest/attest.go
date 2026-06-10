// Package attest provides Ed25519 identity management for the kamune protocol.
// It handles key generation, signing, verification, and serialization
// (PKIX/SPKI for public keys, PKCS8 for private keys).
package attest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
)

var (
	ErrInvalidKey = errors.New("invalid key type")
)

// Attest represents the peer's identity.
type Attest struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

func (e Attest) Sign(msg []byte) ([]byte, error) {
	return ed25519.Sign(e.privateKey, msg), nil
}

func (Attest) Verify(remote, msg, sig []byte) bool {
	return Verify(remote, msg, sig)
}

func (e Attest) MarshalPublicKey() []byte {
	b, err := x509.MarshalPKIXPublicKey(e.publicKey)
	if err != nil {
		panic(fmt.Errorf("marshalling public key: %w", err))
	}
	return b
}

func (e Attest) EncodePublicKey() string {
	return base64.RawURLEncoding.EncodeToString(e.MarshalPublicKey())
}

func (e Attest) MarshalPrivateKey() ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(e.privateKey)
}

func New() (*Attest, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Attest{privateKey: private, publicKey: public}, nil
}

func Load(data []byte) (*Attest, error) {
	key, err := x509.ParsePKCS8PrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("parsing key: %w", err)
	}
	private, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	return &Attest{
		privateKey: private,
		publicKey:  private.Public().(ed25519.PublicKey),
	}, nil
}

func Verify(remote, msg, sig []byte) bool {
	p, err := parsePublicKey(remote)
	if err == nil {
		return ed25519.Verify(p, msg, sig)
	}
	return false
}

func IsValidPublicKey(b []byte) bool {
	_, err := parsePublicKey(b)
	return err == nil
}

func parsePublicKey(key []byte) (ed25519.PublicKey, error) {
	pk, err := x509.ParsePKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	edPub, ok := pk.(ed25519.PublicKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	return edPub, nil
}
