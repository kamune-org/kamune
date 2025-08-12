package attest

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

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

type Attestation int

const (
	invalidAttestation Attestation = iota
	Ed25519
	MLDSA
)

type Attester interface {
	PublicKey() PublicKey
	Sign(msg []byte) ([]byte, error)
	Save(path string) error
}

type PublicKey interface {
	Marshal() []byte
	Base64Encoding() string
	Equal(PublicKey) bool
}

func (a Attestation) New() (Attester, error) {
	switch a {
	case Ed25519:
		return newEd25519DSA()
	case MLDSA:
		return newMLDSA()
	default:
		panic(fmt.Errorf("invalid attestation: %d", a))
	}
}

func (a Attestation) Verify(pub PublicKey, msg, sig []byte) bool {
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
		panic(fmt.Errorf("attest.Verify: invalid attestation: %d", a))
	}
}

func (a Attestation) ParsePublicKey(remote []byte) (PublicKey, error) {
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
		panic(fmt.Errorf("attest.ParsePublicKey: invalid attestation: %d", a))
	}
}

func (a Attestation) LoadFromDisk(path string) (Attester, error) {
	switch a {
	case Ed25519:
		return loadEd25519(path)
	case MLDSA:
		return loadMLDSA(path)
	default:
		panic(fmt.Errorf("attest.LoadFromDisk: invalid attestation: %d", a))
	}
}

func (a Attestation) String() string {
	switch a {
	case Ed25519:
		return "ed25519"
	case MLDSA:
		return "mldsa"
	default:
		panic(fmt.Errorf("unknown attestation algorithm: %d", a))
	}
}

func loadFromDisk(path string) ([]byte, error) {
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

	return block.Bytes, nil
}

func save(private, public []byte, path string) error {
	err := storeKey(private, privateKeyType, path)
	if err != nil {
		return fmt.Errorf("saving private key: %w", err)
	}
	err = storeKey(public, publicKeyType, path+".pub")
	if err != nil {
		return fmt.Errorf("saving public key: %w", err)
	}
	return nil
}

func storeKey(key []byte, kType, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating file: %w", err)
	}
	defer file.Close()

	block := pem.Block{Bytes: key, Type: kType}
	if err = pem.Encode(file, &block); err != nil {
		return fmt.Errorf("encode key: %w", err)
	}

	return nil
}
