package attest

import (
	"fmt"
	"strings"
)

type Algorithm int

const (
	invalidAlgorithm Algorithm = iota
	Ed25519Algorithm
	MLDSAAlgorithm
)

func (alg Algorithm) String() string {
	switch alg {
	case Ed25519Algorithm:
		return "ed25519"
	case MLDSAAlgorithm:
		return "mldsa"
	default:
		panic(fmt.Errorf("unknown algorithm: %d", alg))
	}
}

func (a Algorithm) Identitfier() Identifier {
	switch a {
	case Ed25519Algorithm:
		return Ed25519{}
	case MLDSAAlgorithm:
		return MLDSA{}
	default:
		panic(fmt.Errorf("unknown algorithm: %d", a))
	}
}

func (a *Algorithm) UnmarshalText(text []byte) error {
	var err error
	switch strings.ToLower(string(text)) {
	case "ed25519":
		*a = Ed25519Algorithm
	case "mldsa":
		*a = MLDSAAlgorithm
	default:
		err = fmt.Errorf("unknown algorithm: %s", text)
	}
	return err
}
