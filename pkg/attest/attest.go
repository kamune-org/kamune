package attest

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidKey = errors.New("invalid key type")
)

type Attester interface {
	PublicKey() PublicKey
	Sign(msg []byte) ([]byte, error)
	Save() ([]byte, error)
}

type Identifier interface {
	fmt.Stringer
	Verify(remote PublicKey, msg, sig []byte) bool
	ParsePublicKey(key []byte) (PublicKey, error)
}

type PublicKey interface {
	Marshal() []byte
	Equal(PublicKey) bool
}

func NewAttester(a Algorithm) (Attester, error) {
	switch a {
	case Ed25519Algorithm:
		return newEd25519DSA()
	case MLDSAAlgorithm:
		return newMLDSA()
	default:
		return nil, fmt.Errorf("NewAttest: invalid identity: %v", a)
	}
}

func LoadAttester(a Algorithm, data []byte) (Attester, error) {
	switch a {
	case Ed25519Algorithm:
		return loadEd25519(data)
	case MLDSAAlgorithm:
		return loadMLDSA(data)
	default:
		return nil, fmt.Errorf("invalid algorithm: %d", a)
	}
}
