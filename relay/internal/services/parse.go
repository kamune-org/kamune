package services

import (
	"fmt"

	"github.com/kamune-org/kamune/pkg/attest"
)

// ParsePublicKey parses a raw public key bytes according to the provided
// algorithm and returns an attest.PublicKey instance.
//
// This is a small helper to centralize public-key parsing logic so callers
// don't need to construct concrete identifier types themselves.
func ParsePublicKey(alg attest.Algorithm, key []byte) (attest.PublicKey, error) {
	switch alg {
	case attest.Ed25519Algorithm:
		// ParsePublicKey is defined with a value receiver on the concrete type,
		// so calling it on the zero value is fine.
		return attest.Ed25519{}.ParsePublicKey(key)
	case attest.MLDSAAlgorithm:
		return attest.MLDSA{}.ParsePublicKey(key)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %v", alg)
	}
}

// ParsePublicKeyFor uses the service's configured identity algorithm to parse
// the provided key bytes. It is a convenience wrapper around ParsePublicKey.
func (s *Service) ParsePublicKeyFor(key []byte) (attest.PublicKey, error) {
	return ParsePublicKey(s.cfg.Server.Identity, key)
}
