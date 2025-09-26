package attest

import (
	"errors"
)

var (
	ErrInvalidKey = errors.New("invalid key type")
)

type Attester interface {
	PublicKey() PublicKey
	Sign(msg []byte) ([]byte, error)
	Save() ([]byte, error)
}

type PublicKey interface {
	Marshal() []byte
	Equal(PublicKey) bool
	Identity() Identity
}
