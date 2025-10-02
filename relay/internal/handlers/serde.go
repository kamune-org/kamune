package handlers

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/hossein1376/grape"

	"github.com/kamune-org/kamune/pkg/attest"
)

var (
	ErrMissingPubKey = errors.New("public key param is required")
)

type registerPeerRequest struct {
	PublicKey string          `json:"public_key"`
	Identity  attest.Identity `json:"identity"`
	Addr      []string        `json:"address"`

	publicKey []byte
}

func registerPeerBinder(
	w http.ResponseWriter, r *http.Request,
) (registerPeerRequest, error) {
	var req registerPeerRequest
	err := grape.ReadJson(w, r, &req)
	if err != nil {
		return req, fmt.Errorf("reading json: %w", err)
	}
	pubKey := make([]byte, base64.RawURLEncoding.DecodedLen(len(req.PublicKey)))
	n, err := base64.RawURLEncoding.Decode(pubKey, []byte(req.PublicKey))
	if err != nil {
		return req, fmt.Errorf("decoding public fkey: %w", err)
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
