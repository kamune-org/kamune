package handlers

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/hossein1376/grape"

	"github.com/kamune-org/kamune/pkg/attest"
)

var (
	ErrMissingPubKey = errors.New("public key param is required")
)

type registerPeerRequest struct {
	PublicKey string           `json:"public_key"`
	Identity  attest.Algorithm `json:"algorithm"`
	Addr      []string         `json:"address"`

	publicKey []byte
}

func registerPeerBinder(
	w http.ResponseWriter, r *http.Request,
) (*registerPeerRequest, error) {
	req, err := grape.ReadJSON[registerPeerRequest](w, r)
	if err != nil {
		return nil, fmt.Errorf("reading json: %w", err)
	}
	pubKey := make([]byte, base64.RawURLEncoding.DecodedLen(len(req.PublicKey)))
	n, err := base64.RawURLEncoding.Decode(pubKey, []byte(req.PublicKey))
	if err != nil {
		return req, fmt.Errorf("decoding public key: %w", err)
	}

	req.publicKey = pubKey[:n]
	return req, nil
}

func readKeyFromQuery(q url.Values) ([]byte, error) {
	pubKeyEncoded := []byte(q.Get("key"))
	if len(pubKeyEncoded) == 0 {
		return nil, ErrMissingPubKey
	}
	pubKey := make([]byte, base64.RawURLEncoding.DecodedLen(len(pubKeyEncoded)))
	n, err := base64.RawURLEncoding.Decode(pubKey, pubKeyEncoded)
	if err != nil {
		return nil, fmt.Errorf("decoding public key: %w", err)
	}

	return pubKey[:n], nil
}

// ParseForwardedIP extracts the left-most IP from an X-Forwarded-For header
// and strips any port if present. Returns empty string if header is empty.
func ParseForwardedIP(header string) string {
	if header == "" {
		return ""
	}
	parts := strings.Split(header, ",")
	ip := strings.TrimSpace(parts[0])
	// Strip port if present
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}
	return ip
}
