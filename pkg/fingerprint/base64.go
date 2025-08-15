package fingerprint

import (
	"encoding/base64"
)

func Base64(b []byte) string {
	return base64.RawStdEncoding.EncodeToString(b)
}
