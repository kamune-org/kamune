package handlers

import (
	"encoding/base64"
	"fmt"

	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/relay/internal/services"
)

// DecodeBase64Raw decodes a base64.RawURLEncoding encoded string and returns the
// raw bytes. Returns a wrapped error with context when decoding fails or input
// is empty.
func DecodeBase64Raw(s string) ([]byte, error) {
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

// ParsePublicKeyFromBase64 decodes a base64-encoded public key (raw PK bytes,
// using RawURLEncoding) and parses it into an attest.PublicKey using the
// provided service's parsing helper.
//
// This centralizes the common pattern of base64-decoding a key and then
// converting it into the library's PublicKey representation.
func ParsePublicKeyFromBase64(enc string, svc *services.Service) (attest.PublicKey, error) {
	raw, err := DecodeBase64Raw(enc)
	if err != nil {
		return nil, err
	}
	pk, err := svc.ParsePublicKeyFor(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}
	return pk, nil
}

// DecodePayloadFromBase64 decodes a base64.RawURLEncoding-encoded payload.
// This is a thin wrapper over DecodeBase64Raw for clearer intent when used by
// handlers that operate over message payloads.
func DecodePayloadFromBase64(enc string) ([]byte, error) {
	return DecodeBase64Raw(enc)
}

// EncodePayloadToBase64 encodes raw payload bytes into a base64.RawURLEncoding
// encoded string. This provides a symmetric helper to DecodePayloadFromBase64
// for handlers that need to return base64-encoded payloads.
func EncodePayloadToBase64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// DecodeAndParsePair decodes two base64-encoded public keys (sender and
// receiver) and parses them using the given service. It returns the parsed
// sender and receiver PublicKey values (in that order) or an error.
func DecodeAndParsePair(senderEnc, receiverEnc string, svc *services.Service) (attest.PublicKey, attest.PublicKey, error) {
	senderPK, err := ParsePublicKeyFromBase64(senderEnc, svc)
	if err != nil {
		return nil, nil, fmt.Errorf("sender key: %w", err)
	}
	receiverPK, err := ParsePublicKeyFromBase64(receiverEnc, svc)
	if err != nil {
		return nil, nil, fmt.Errorf("receiver key: %w", err)
	}
	return senderPK, receiverPK, nil
}
