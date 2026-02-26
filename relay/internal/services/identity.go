package services

import (
	"encoding/base64"
	"strings"

	"github.com/kamune-org/kamune/pkg/fingerprint"
)

// IdentityFormat enumerates the supported public key encoding formats
// for the /identity endpoint.
type IdentityFormat string

const (
	FormatBase64      IdentityFormat = "base64"
	FormatHex         IdentityFormat = "hex"
	FormatEmoji       IdentityFormat = "emoji"
	FormatFingerprint IdentityFormat = "fingerprint"
)

// IdentityResponse holds the relay server's public key encoded in the
// requested format along with metadata about the encoding used.
type IdentityResponse struct {
	Key       string `json:"key"`
	Format    string `json:"format"`
	Algorithm string `json:"algorithm"`
}

// PublicKey returns the relay's public key as a base64 raw-URL string.
func (s *Service) PublicKey() string {
	return base64.RawURLEncoding.EncodeToString(s.attester.PublicKey().Marshal())
}

// Identity returns the relay's public key encoded in the requested format.
// Supported formats:
//   - "base64" (default): base64 raw-URL encoding of the raw public key bytes
//   - "hex": colon-separated uppercase hex (e.g. "AB:CD:EF:...")
//   - "emoji": 8 emoji symbols derived from a SHA-256 hash, joined with " • "
//   - "fingerprint": base64 raw-URL encoded SHA-256 digest of the public key
//
// An unrecognised format string silently falls back to "base64".
func (s *Service) Identity(format string) IdentityResponse {
	raw := s.attester.PublicKey().Marshal()
	alg := s.cfg.Server.Identity.String()

	switch IdentityFormat(strings.ToLower(strings.TrimSpace(format))) {
	case FormatHex:
		return IdentityResponse{
			Key:       fingerprint.Hex(raw),
			Format:    string(FormatHex),
			Algorithm: alg,
		}
	case FormatEmoji:
		return IdentityResponse{
			Key:       strings.Join(fingerprint.Emoji(raw), " • "),
			Format:    string(FormatEmoji),
			Algorithm: alg,
		}
	case FormatFingerprint:
		return IdentityResponse{
			Key:       fingerprint.Sum(raw),
			Format:    string(FormatFingerprint),
			Algorithm: alg,
		}
	default:
		return IdentityResponse{
			Key:       fingerprint.Base64(raw),
			Format:    string(FormatBase64),
			Algorithm: alg,
		}
	}
}
