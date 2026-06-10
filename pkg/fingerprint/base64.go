package fingerprint

import (
	"encoding/base64"
)

// Base64 encodes b as a raw URL-safe base64 string (no padding).
func Base64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
