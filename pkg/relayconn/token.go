package relayconn

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/pkg/exchange"
	"google.golang.org/protobuf/proto"
)

const (
	// relayTokenSize is the length in bytes of relay-generated session tokens
	// assigned by the relay via Create(). User-provided tokens (static and
	// ECDH-derived) use peerTokenSize.
	relayTokenSize = 16

	// peerTokenSize is the required length in bytes of user-provided tokens
	// (static tokens from TokenFromKeys and ECDH-derived tokens from
	// DeriveRelayTokens). The relay rejects tokens of any other length.
	peerTokenSize = 32

	// tokenPoolSize is the number of tokens derived from a single ECDH
	// exchange. The dialer searches the pool sequentially on reconnect.
	tokenPoolSize = 3

	// tokenInfoPrefix is the HKDF info prefix for relay reconnect tokens.
	tokenInfoPrefix = "kamune/relay-reconnect/v1/"
)

var (
	// ErrInvalidKeySize is returned by TokenFromKeys when either input public
	// key is not exactly ed25519.PublicKeySize bytes.
	ErrInvalidKeySize = errors.New(
		"public key must be ed25519.PublicKeySize bytes",
	)

	// ErrTokenTooShort is returned by ValidateUserToken when the token is not
	// exactly peerTokenSize bytes.
	ErrTokenTooShort = errors.New("token must be 32 bytes")

	// ErrTokenInsufficientEntropy is returned by ValidateUserToken when the
	// token fails the Shannon entropy check (< 3 bits/byte).
	ErrTokenInsufficientEntropy = errors.New("token has insufficient entropy")

	// ErrECDHPeerKeyMissing is returned by DeriveRelayTokens when the peer's
	// SessionData message does not contain an "ecdh_pubkey" field.
	ErrECDHPeerKeyMissing = errors.New("peer SessionData missing ecdh_pubkey")

	// ErrInvalidRelayToken is returned by the Listen helpers when the relay
	// assigns a token that is empty or neither 16 nor 32 bytes long.
	ErrInvalidRelayToken = errors.New("relay returned an invalid token")

	// ErrRelayTokenMismatch is returned by the Listen and Dial helpers when
	// the relay's Registered frame echoes a token other than the one the
	// client registered with.
	ErrRelayTokenMismatch = errors.New("relay returned a different token")
)

// checkRegisteredToken validates the token in the relay's Registered
// frame. When the client sent a token, the relay must echo it unchanged.
// Otherwise the relay assigned one, which must have a known length.
func checkRegisteredToken(got, sent []byte) error {
	if len(sent) > 0 {
		if !bytes.Equal(got, sent) {
			return ErrRelayTokenMismatch
		}
		return nil
	}
	if len(got) != relayTokenSize && len(got) != peerTokenSize {
		return fmt.Errorf("%w: %d bytes", ErrInvalidRelayToken, len(got))
	}
	return nil
}

// ValidateUserToken checks that a user-provided token meets the relay's
// requirements: exactly 32 bytes, non-zero, not all the same byte, and Shannon
// entropy above 3 bits per byte.
func ValidateUserToken(token []byte) error {
	if len(token) != peerTokenSize {
		return ErrTokenTooShort
	}

	// Non-zero check.
	allZero := true
	for _, b := range token {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return ErrTokenInsufficientEntropy
	}

	// Constant-byte check.
	constByte := token[0]
	allSame := true
	for _, b := range token[1:] {
		if b != constByte {
			allSame = false
			break
		}
	}
	if allSame {
		return ErrTokenInsufficientEntropy
	}

	// Shannon entropy check: > 3 bits/byte.
	var freq [256]float64
	for _, b := range token {
		freq[b]++
	}
	var entropy float64
	n := float64(len(token))
	for _, f := range freq {
		if f > 0 {
			p := f / n
			entropy -= p * log2(p)
		}
	}
	if entropy <= 3 {
		return ErrTokenInsufficientEntropy
	}

	return nil
}

func log2(x float64) float64 {
	// log2(x) = ln(x) / ln(2)
	const ln2 = 0.6931471805599453
	return math.Log(x) / ln2
}

// TokenFromKeys returns a 32-byte session token derived from two peers' public
// keys. The token is order-independent:
//
//	TokenFromKeys(A, B) == TokenFromKeys(B, A).
//
// Both peers must use ed25519 public keys of the standard 32-byte size to
// compute the same token.
func TokenFromKeys(a, b ed25519.PublicKey) ([]byte, error) {
	if len(a) != ed25519.PublicKeySize || len(b) != ed25519.PublicKeySize {
		return nil, ErrInvalidKeySize
	}
	lo, hi := a, b
	if bytes.Compare(a, b) > 0 {
		lo, hi = b, a
	}
	h := sha256.New()
	h.Write(lo)
	h.Write(hi)
	return h.Sum(nil), nil
}

// RelayTokenPending is one side of a relay-token ECDH exchange.
// The shared secret is not stored.
type RelayTokenPending struct {
	local *exchange.ECDH
}

// BeginRelayTokenExchange sends this side's ephemeral public key.
// It does not read the next frame and does not set a deadline.
func BeginRelayTokenExchange(
	transport *kamune.Transport,
) (*RelayTokenPending, error) {
	localKey, err := exchange.NewECDH()
	if err != nil {
		return nil, fmt.Errorf("generating ecdh key: %w", err)
	}
	_, err = transport.Send(&pb.SessionData{
		Fields: map[string][]byte{
			"ecdh_pubkey": localKey.MarshalPublicKey(),
		},
	}, kamune.RouteSessionData)
	if err != nil {
		return nil, fmt.Errorf("sending ecdh pubkey: %w", err)
	}
	return &RelayTokenPending{local: localKey}, nil
}

// Complete derives the reconnect pool from the peer's public key.
func (p *RelayTokenPending) Complete(
	peerPub []byte,
) ([tokenPoolSize][32]byte, error) {
	var zero [tokenPoolSize][32]byte
	sharedSecret, err := p.local.Exchange(peerPub)
	if err != nil {
		return zero, fmt.Errorf("ecdh exchange: %w", err)
	}

	// The X25519 shared secret is already uniform, so it is the PRK.
	var tokens [tokenPoolSize][32]byte
	for i := range uint32(tokenPoolSize) {
		info := make([]byte, len(tokenInfoPrefix)+4)
		copy(info, tokenInfoPrefix)
		binary.BigEndian.PutUint32(
			info[len(tokenInfoPrefix):], i,
		)
		tok, err := hkdf.Expand(
			sha512.New, sharedSecret, string(info), 32,
		)
		if err != nil {
			return zero, fmt.Errorf("hkdf expand token %d: %w", i, err)
		}
		copy(tokens[i][:], tok)
	}
	return tokens, nil
}

// CompleteRelayTokenPayload unmarshals a RouteSessionData payload and
// derives the pool. Clients use it because SessionData is not exported.
func CompleteRelayTokenPayload(
	p *RelayTokenPending, payload []byte,
) ([tokenPoolSize][32]byte, error) {
	var zero [tokenPoolSize][32]byte
	if p == nil {
		return zero, errors.New("no pending relay token")
	}
	var msg pb.SessionData
	if err := proto.Unmarshal(payload, &msg); err != nil {
		return zero, fmt.Errorf("session data: %w", err)
	}
	key, ok := SessionDataPeerKey(&msg)
	if !ok {
		return zero, ErrECDHPeerKeyMissing
	}
	return p.Complete(key)
}

// SessionDataPeerKey returns the ecdh_pubkey field when it is present.
func SessionDataPeerKey(msg *pb.SessionData) ([]byte, bool) {
	if msg == nil {
		return nil, false
	}
	key, ok := msg.Fields["ecdh_pubkey"]
	if !ok || len(key) == 0 {
		return nil, false
	}
	return key, true
}

// DeriveRelayTokens performs an ephemeral ECDH key exchange over the given
// transport and derives a pool of 3 reconnect tokens. Both peers must call this
// concurrently — the exchange is synchronous (send then receive) so each peer
// must send before the other's receive completes.
//
// DeriveRelayTokens takes the next frame from transport, so no other goroutine
// may receive on it meanwhile. That frame must be the peer's SessionData: a
// frame on any other route is consumed and reported as an error wrapping
// kamune.ErrUnexpectedRoute that names the route. The exchange runs under a
// 5-second Transport deadline, which also applies to concurrent sends, and the
// deadline is cleared on return, replacing any deadline the caller had set.
//
// The shared secret is never stored. Tokens are derived via HKDF and stored by
// the caller in persistent storage.
//
// Deprecated: a frame the peer sends first, such as a chat message, is lost.
// Call BeginRelayTokenExchange and pass the peer's RouteSessionData payload
// from the receive loop to CompleteRelayTokenPayload instead.
func DeriveRelayTokens(
	transport *kamune.Transport,
) ([tokenPoolSize][32]byte, error) {
	var zero [tokenPoolSize][32]byte

	_ = transport.SetDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = transport.SetDeadline(time.Time{}) }()

	pending, err := BeginRelayTokenExchange(transport)
	if err != nil {
		return zero, err
	}

	md, payload, err := transport.ReceivePayload()
	if err != nil {
		return zero, fmt.Errorf("receiving ecdh pubkey: %w", err)
	}
	if route := md.Route(); route != kamune.RouteSessionData {
		return zero, fmt.Errorf(
			"receiving ecdh pubkey: %w: %s", kamune.ErrUnexpectedRoute, route,
		)
	}
	return CompleteRelayTokenPayload(pending, payload)
}
