package attest

import (
	"crypto/x509"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"golang.org/x/crypto/ed25519"
)

type Identity int64

const (
	invalidIdentity Identity = iota
	Ed25519
	MLDSA
)

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
		panic(fmt.Errorf("invalid identity: %d", a))
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
		panic(fmt.Errorf("invalid identity: %d", a))
	}
}

func (a Identity) Load(data []byte) (Attester, error) {
	switch a {
	case Ed25519:
		return loadEd25519(data)
	case MLDSA:
		return loadMLDSA(data)
	default:
		panic(fmt.Errorf("invalid identity: %d", a))
	}
}

func (a Identity) String() string {
	switch a {
	case Ed25519:
		return "ed25519"
	case MLDSA:
		return "mldsa"
	default:
		panic(fmt.Errorf("invalid identity: %d", a))
	}
}

func ParseIdentity(s string) (Identity, error) {
	switch s {
	case "ed25519":
		return Ed25519, nil
	case "mldsa":
		return MLDSA, nil
	default:
		return invalidIdentity, fmt.Errorf("unknown identity: %s", s)
	}
}
