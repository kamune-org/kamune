package attest

import (
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"golang.org/x/crypto/ed25519"
)

const (
	publicKeyType  = "PUBLIC KEY"
	privateKeyType = "PRIVATE KEY"
)

var (
	ErrMissingPEM  = errors.New("no PEM data found")
	ErrMissingFile = errors.New("file not found")
	ErrInvalidKey  = errors.New("invalid key type")
)

type Identity int

const (
	invalidIdentity Identity = iota
	Ed25519
	MLDSA
)

type Attester interface {
	PublicKey() PublicKey
	Sign(msg []byte) ([]byte, error)
	Save() ([]byte, error)
}

type PublicKey interface {
	Marshal() []byte
	Equal(PublicKey) bool
}

func (a Identity) NewAttest() (Attester, error) {
	switch a {
	case Ed25519:
		return newEd25519DSA()
	case MLDSA:
		return newMLDSA()
	default:
		panic(fmt.Errorf("NewAttest: invalid identity: %d", a))
	}
}

func (a Identity) Verify(pub PublicKey, msg, sig []byte) bool {
	switch a {
	case Ed25519:
		p, ok := pub.(*ed25519PublicKey)
		if !ok {
			return false
		}
		return ed25519.Verify(p.key, msg, sig)
	case MLDSA:
		p, ok := pub.(*mldsaPublicKey)
		if !ok {
			return false
		}
		return mldsa65.Verify(p.key, msg, nil, sig)
	default:
		panic(fmt.Errorf("Verify: invalid identity: %d", a))
	}
}

func (a Identity) ParsePublicKey(remote []byte) (PublicKey, error) {
	switch a {
	case Ed25519:
		pk, err := x509.ParsePKIXPublicKey(remote)
		if err != nil {
			return nil, fmt.Errorf("parse: %w", err)
		}
		edPub, ok := pk.(ed25519.PublicKey)
		if !ok {
			return nil, ErrInvalidKey
		}
		return &ed25519PublicKey{key: edPub}, nil
	case MLDSA:
		mlPub, err := mldsa65.Scheme().UnmarshalBinaryPublicKey(remote)
		if err != nil {
			return nil, err
		}
		return &mldsaPublicKey{mlPub.(*mldsa65.PublicKey)}, nil
	default:
		panic(fmt.Errorf("ParsePublicKey: invalid identity: %d", a))
	}
}

func (a Identity) Load(data []byte) (Attester, error) {
	switch a {
	case Ed25519:
		return loadEd25519(data)
	case MLDSA:
		return loadMLDSA(data)
	default:
		panic(fmt.Errorf("Load: invalid identity: %d", a))
	}
}

func (a Identity) String() string {
	switch a {
	case Ed25519:
		return "ed25519"
	case MLDSA:
		return "mldsa"
	default:
		panic(fmt.Errorf("String: invalid identity: %d", a))
	}
}
