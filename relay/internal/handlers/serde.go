package handlers

import (
	"encoding/base64"
	"fmt"

	"github.com/kamune-org/kamune/pkg/attest"
)

// decodeBase64Raw decodes a base64.RawURLEncoding encoded string and returns the
// raw bytes. Returns a wrapped error with context when decoding fails or input
// is empty.
func decodeBase64Raw(s string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("empty base64 input")
	}
	dst := make([]byte, base64.RawURLEncoding.DecodedLen(len(s)))
	n, err := base64.RawURLEncoding.Decode(dst, []byte(s))
	if err != nil {
		return nil, fmt.Errorf("decoding base64: %w", err)
	}
	return dst[:n], nil
}

// encodePayloadToBase64 encodes raw payload bytes into a base64.RawURLEncoding
// encoded string. This provides a symmetric helper to DecodePayloadFromBase64
// for handlers that need to return base64-encoded payloads.
func encodePayloadToBase64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// parsePublicKey parses a raw public key bytes according to the provided
// algorithm and returns an attest.PublicKey instance.
//
// This is a small helper to centralize public-key parsing logic so callers
// don't need to construct concrete identifier types themselves.
func parsePublicKey(alg attest.Algorithm, key []byte) (attest.PublicKey, error) {
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
