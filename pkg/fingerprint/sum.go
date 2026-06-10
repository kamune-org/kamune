// Package fingerprint provides human-readable representations of identity
// keys: base64 fingerprints, hex with colon separators, emoji sequences,
// and human-readable pseudonyms.
package fingerprint

import (
	"crypto/sha256"
)

// Sum returns the SHA-256 hash of b encoded as a base64url fingerprint.
func Sum(b []byte) string {
	sum := sha256.Sum256(b)
	return Base64(sum[:])
}
