package relayleg

import (
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
)

const (
	relayPrefix = "rk1-"
	pskPrefix   = "psk1-"

	rawKeyLen  = 32
	textKeyLen = 52
)

// base32Raw is the RFC 4648 alphabet with no padding.
var base32Raw = base32.StdEncoding.WithPadding(base32.NoPadding)

func encodeRaw(raw []byte) string {
	return strings.ToLower(base32Raw.EncodeToString(raw))
}

// group4 inserts a dash between every four characters of s.
func group4(s string) string {
	var b strings.Builder
	b.Grow(len(s) + len(s)/4)
	for i := 0; i < len(s); i += 4 {
		if i > 0 {
			b.WriteByte('-')
		}
		end := min(i+4, len(s))
		b.WriteString(s[i:end])
	}
	return b.String()
}

// parseFixedKey parses prefix plus 32 bytes of canonical base32.
// Every error wraps sentinel.
func parseFixedKey(s, prefix string, sentinel error) ([32]byte, error) {
	var zero [32]byte
	s = strings.TrimSpace(s)
	if len(s) < len(prefix) ||
		!strings.EqualFold(s[:len(prefix)], prefix) {
		return zero, fmt.Errorf("%w: prefix", sentinel)
	}
	raw, err := decodeCanonical(s[len(prefix):])
	if err != nil {
		return zero, fmt.Errorf("%w: %w", sentinel, err)
	}
	if raw == zero {
		return zero, fmt.Errorf("%w: all zero", sentinel)
	}
	return raw, nil
}

// decodeCanonical accepts upper or lower case and ignores dashes and
// spaces. 52 base32 characters hold 260 bits and a key is 256 bits, so
// the last character has 4 unused low bits. The decoder drops those
// bits. Re-encoding keeps the one spelling whose unused bits are zero.
func decodeCanonical(body string) ([32]byte, error) {
	var zero [32]byte
	cleaned := make([]byte, 0, len(body))
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case c == '-' || c == ' ':
			continue
		case c >= 'a' && c <= 'z':
			cleaned = append(cleaned, c-('a'-'A'))
		case (c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7'):
			cleaned = append(cleaned, c)
		default:
			return zero, errors.New("non-base32 character")
		}
	}
	if len(cleaned) != textKeyLen {
		return zero, fmt.Errorf("base32 length %d", len(cleaned))
	}
	raw := make([]byte, rawKeyLen)
	n, err := base32Raw.Decode(raw, cleaned)
	if err != nil {
		return zero, fmt.Errorf("decode: %w", err)
	}
	if n != rawKeyLen {
		return zero, fmt.Errorf("decoded length %d", n)
	}
	if base32Raw.EncodeToString(raw) != string(cleaned) {
		return zero, errors.New("non-zero unused bits")
	}
	var out [32]byte
	copy(out[:], raw)
	return out, nil
}
