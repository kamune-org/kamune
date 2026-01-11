package fingerprint

import (
	"crypto/sha256"
)

func Sum(b []byte) string {
	sum := sha256.Sum256(b)
	return Base64(sum[:])
}
