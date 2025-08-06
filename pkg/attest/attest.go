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

type Attest interface {
	PublicKey() PublicKey
	Sign(msg, ctx []byte) ([]byte, error)
	Save(path string) error
}

type PublicKey interface {
	Marshal() []byte
	Base64Encoding() string
	Equal(PublicKey) bool
}

func Verify(publicKey PublicKey, msg, sig []byte) bool {
	switch p := publicKey.(type) {
	default:
		return false
	case *mldsaPublicKey:
		return mldsa65.Verify(p.key, msg, nil, sig)
	case *ed25519PublicKey:
		return ed25519.Verify(p.key, msg, sig)
	}
}

func ParsePublicKey(remote []byte) (PublicKey, error) {
	mlPub, err := mldsa65.Scheme().UnmarshalBinaryPublicKey(remote)
	if err == nil {
		return &mldsaPublicKey{mlPub.(*mldsa65.PublicKey)}, nil
	}

	pk, err := x509.ParsePKIXPublicKey(remote)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	edPub, ok := pk.(ed25519.PublicKey)
	if ok {
		return &ed25519PublicKey{key: edPub}, nil
	}

	return nil, ErrInvalidKey
}

func LoadFromDisk(path string) (Attest, error) {
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

	mlPrivate, err := mldsa65.Scheme().UnmarshalBinaryPrivateKey(block.Bytes)
	if err == nil {
		return &MLDSA{
			privateKey: mlPrivate.(*mldsa65.PrivateKey),
			publicKey:  mlPrivate.Public().(*mldsa65.PublicKey),
		}, nil
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing key: %w", err)
	}
	edPrivate, ok := key.(ed25519.PrivateKey)
	if ok {
		return &Ed25519{
			privateKey: edPrivate,
			publicKey:  edPrivate.Public().(ed25519.PublicKey),
		}, nil
	}

	return nil, ErrInvalidKey
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
