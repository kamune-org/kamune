// Package fingerprint provides human-readable representations of identity
// keys: base64 fingerprints, hex with colon separators, emoji sequences,
// decimal numeric fingerprints and human-readable pseudonyms.
//
// For people to verify a key, compare [Numeric], which carries about 132.9
// bits. [Emoji] carries about 52.7 bits, too few on its own against an
// attacker who searches for a key with the same emojis.
package fingerprint

import (
	"crypto/sha256"
)

// Sum returns the SHA-256 hash of b encoded as a base64url fingerprint.
func Sum(b []byte) string {
	sum := sha256.Sum256(b)
	return Base64(sum[:])
}
