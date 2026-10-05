package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/relayconn"
	relaybroker "github.com/kamune-org/kamune/pkg/relayconn/broker"
	"github.com/kamune-org/kamune/pkg/storage"
)

const (
	// p2pTokenRefreshInterval is how often a p2p listener refreshes the
	// broker registrations of its tokens.
	p2pTokenRefreshInterval = 30 * time.Second
	// p2pTokenTTL is how long the broker keeps a registration after its
	// last REGISTER: the relay broker's default registration TTL. A
	// token expires that long after its last refresh, so while refreshes
	// go out its expiry stays a refresh interval ahead.
	p2pTokenTTL = 60 * time.Second
	// defaultMatchTimeout bounds how long a p2p dial waits for the
	// broker to match its token with the server's.
	defaultMatchTimeout = 30 * time.Second
)

// maxP2PTokens caps the tokens that a p2p server registers, its own
// included. The listener sends a REGISTER for each of its tokens every
// p2pTokenRefreshInterval from one address, and the broker drops,
// without a word, the REGISTERs of a source address past its quota,
// which is 20 a minute by default: past about 10 tokens, some would
// lapse while p2p_tokens lists them as live. 8 leaves room for the
// REGISTERs of dials and of a new token.
const maxP2PTokens = 8

// errTooManyP2PTokens is returned by GenerateP2PToken while the p2p
// server registers maxP2PTokens tokens.
var errTooManyP2PTokens = fmt.Errorf(
	"a p2p server registers at most %d tokens; remove one first",
	maxP2PTokens,
)

// errInvalidP2PToken is returned by parseP2PToken.
var errInvalidP2PToken = errors.New(
	"p2p_token must be 32 or 64 hex characters",
)

// parseP2PToken decodes a p2p token given to dial: a random token the
// broker assigned (16 bytes) or a static one derived from two peers'
// keys (32 bytes), in hex.
func parseP2PToken(s string) ([]byte, error) {
	token, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errInvalidP2PToken, err)
	}
	if len(token) != relaybroker.TokenSize && len(token) != 32 {
		return nil, errInvalidP2PToken
	}
	return token, nil
}

type p2pToken struct {
	Token      string        `json:"token"`
	Consumed   bool          `json:"consumed"`
	TTL        time.Duration `json:"ttl_ns"`
	ExpiresAt  time.Time     `json:"expires_at"`
	Mode       string        `json:"mode"`
	PeerPubB64 string        `json:"peer_pub_b64,omitempty"`
	brokerAddr string        `json:"-"`
}

// errNoP2PServer is returned by GenerateP2PToken when no p2p server
// runs. The broker gives a matched peer the address that the token was
// registered from, so only the punch socket of the server that accepts
// the peer can register a token.
var errNoP2PServer = errors.New(
	"generate_p2p_token needs a running p2p server",
)

// errBrokerMismatch is returned by GenerateP2PToken for a broker other
// than the one the p2p server registers with.
var errBrokerMismatch = errors.New(
	"broker_addr is not the p2p server's broker",
)

func (d *Daemon) getOrCreateBrokerClient() (*BrokerClient, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.brokerClient != nil {
		return d.brokerClient, nil
	}
	client, err := NewBrokerClient()
	if err != nil {
		return nil, err
	}
	d.brokerClient = client
	return client, nil
}

// GenerateP2PToken adds a token to the running p2p server: a static one
// derived from the local key and peerPubB64, or a random one when
// peerPubB64 is empty. The server's p2p listener registers and refreshes
// it from its punch socket, the address that a peer who dials the token
// is told to punch to. brokerAddr must be the server's broker.
//
// A static token that the server has already is returned as it is. A
// random token is new on every call, so that each peer it is given to
// gets a token of its own, which can be removed without the others.
func (d *Daemon) GenerateP2PToken(
	brokerAddr, peerPubB64 string,
) (string, error) {
	if brokerAddr == "" {
		return "", errors.New("broker address is required")
	}
	d.mu.RLock()
	l, ok := d.p2pListener.(*p2pListener)
	d.mu.RUnlock()
	if !ok {
		return "", errNoP2PServer
	}
	if brokerAddr != l.brokerAddr {
		return "", fmt.Errorf(
			"%w: the server uses %s", errBrokerMismatch, l.brokerAddr,
		)
	}

	staticToken, err := d.deriveP2PToken(peerPubB64)
	if err != nil {
		return "", err
	}

	if staticToken != nil {
		hexToken := hex.EncodeToString(staticToken)
		d.mu.RLock()
		listed := slices.ContainsFunc(d.p2pTokens, func(t p2pToken) bool {
			return t.brokerAddr == brokerAddr && t.Token == hexToken
		})
		d.mu.RUnlock()
		if listed {
			return hexToken, nil
		}
	}

	token, mode := staticToken, "static"
	if token == nil {
		// The broker holds a random token that the daemon picks as it
		// holds one it assigns. It would send TOKEN_ASSIGNED to the
		// punch socket, which KCP reads.
		token = make([]byte, relaybroker.TokenSize)
		if _, err := rand.Read(token); err != nil {
			return "", fmt.Errorf("random token: %w", err)
		}
		mode = "random"
	}
	var peerKey []byte
	if staticToken != nil {
		// deriveP2PToken checked the key.
		peerKey, _ = decodeValidPeerKey(peerPubB64)
	}
	if err := l.RegisterToken(token, peerKey); err != nil {
		return "", fmt.Errorf("register token on punch socket: %w", err)
	}

	hexToken := hex.EncodeToString(token)
	d.mu.Lock()
	if d.p2pListener != l {
		// The server stopped meanwhile and closed l.
		d.mu.Unlock()
		return "", errNoP2PServer
	}
	d.p2pTokens = append(d.p2pTokens, p2pToken{
		Token:      hexToken,
		Mode:       mode,
		PeerPubB64: peerPubB64,
		TTL:        p2pTokenTTL,
		ExpiresAt:  time.Now().Add(p2pTokenTTL),
		brokerAddr: brokerAddr,
	})
	snapshot := d.p2pTokensSnapshot()
	d.mu.Unlock()

	d.emit(EvtP2PTokens, "", MapA{"tokens": snapshot})
	d.addLogEntry("INFO", "Generated p2p token: "+shortToken(hexToken))
	return hexToken, nil
}

func (d *Daemon) deriveP2PToken(peerPubB64 string) ([]byte, error) {
	if peerPubB64 == "" {
		return nil, nil
	}
	store := d.store()
	if store == nil {
		return nil, errors.New("storage is not available")
	}

	myPubPKIX, err := store.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("get identity: %w", err)
	}
	myPubRaw, err := parsePeerPubB64ToRaw(fingerprint.Base64(myPubPKIX))
	if err != nil {
		return nil, fmt.Errorf("decode local public key: %w", err)
	}
	peerPubRaw, err := parsePeerPubB64ToRaw(peerPubB64)
	if err != nil {
		return nil, err
	}
	t, err := relayconn.TokenFromKeys(myPubRaw, peerPubRaw)
	if err != nil {
		return nil, fmt.Errorf("derive static token: %w", err)
	}
	return t, nil
}

// p2pRefreshed extends the expiry of the tokens of l, the running p2p
// listener, whose registrations were refreshed at at, and emits the
// token list.
func (d *Daemon) p2pRefreshed(l *p2pListener, at time.Time) {
	d.mu.Lock()
	if d.p2pListener != l {
		d.mu.Unlock()
		return
	}
	for i := range d.p2pTokens {
		d.p2pTokens[i].ExpiresAt = at.Add(p2pTokenTTL)
	}
	snapshot := d.p2pTokensSnapshot()
	d.mu.Unlock()
	d.emit(EvtP2PTokens, "", MapA{"tokens": snapshot})
}

func (d *Daemon) RemoveP2PToken(token string) error {
	d.mu.Lock()
	idx := -1
	for i, t := range d.p2pTokens {
		if t.Token == token {
			idx = i
			break
		}
	}
	if idx == -1 {
		d.mu.Unlock()
		return errors.New("token not found")
	}
	pt := d.p2pTokens[idx]
	d.p2pTokens = append(d.p2pTokens[:idx], d.p2pTokens[idx+1:]...)
	snapshot := d.p2pTokensSnapshot()
	listener := d.p2pListener
	d.mu.Unlock()

	unregisterP2PToken(listener, pt.Token)
	d.emit(EvtP2PTokens, "", MapA{"tokens": snapshot})
	d.addLogEntry("INFO", "Removed p2p token: "+shortToken(token))
	return nil
}

// unregisterP2PToken stops listener, when it is a p2p listener, from
// registering the hex token with the broker.
func unregisterP2PToken(listener kamune.Listener, hexToken string) {
	l, ok := listener.(*p2pListener)
	if !ok {
		return
	}
	if token, err := hex.DecodeString(hexToken); err == nil {
		l.UnregisterToken(token)
	}
}

func (d *Daemon) GetP2PTokens() []p2pToken {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.p2pTokensSnapshot()
}

func (d *Daemon) p2pTokensSnapshot() []p2pToken {
	out := make([]p2pToken, len(d.p2pTokens))
	copy(out, d.p2pTokens)
	return out
}

func (d *Daemon) stopP2PResources() {
	d.mu.Lock()
	listener := d.p2pListener
	d.p2pListener = nil
	tokens := d.p2pTokens
	d.p2pTokens = nil
	d.mu.Unlock()

	if listener != nil {
		_ = listener.Close()
	}
	if listener != nil || len(tokens) > 0 {
		d.emit(EvtP2PTokens, "", MapA{"tokens": []p2pToken{}})
	}
}

// errInvalidPeerKey is returned by decodeValidPeerKey for a key that
// attest.IsValidPublicKey refuses.
var errInvalidPeerKey = errors.New(
	"public key is not a valid Ed25519 key",
)

// decodePeerPubKey decodes a peer's PKIX public key from base64. It checks
// only the length, so that a stored peer whose key is not valid can still
// be looked up, renamed and deleted; decodeValidPeerKey checks the key.
func decodePeerPubKey(publicKeyB64 string) ([]byte, error) {
	cleaned := publicKeyB64
	cleaned = strings.TrimSpace(cleaned)
	if cleaned == "" {
		return nil, errors.New("public key is required")
	}
	cleaned = strings.TrimRight(cleaned, "=")
	pub, err := base64.RawURLEncoding.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("decode base64: %w", err)
	}
	if len(pub) != 44 {
		return nil, fmt.Errorf(
			"public key must be 44 bytes (PKIX), got %d", len(pub),
		)
	}
	return pub, nil
}

// decodeValidPeerKey decodes a peer's public key as decodePeerPubKey does,
// and fails with errInvalidPeerKey unless it is a PKIX-encoded Ed25519
// key that attest.IsValidPublicKey accepts: a canonical point whose order
// is not small. A small-order key would let anyone forge signatures under
// it, and a non-canonical one would give one key several fingerprints.
func decodeValidPeerKey(publicKeyB64 string) ([]byte, error) {
	pub, err := decodePeerPubKey(publicKeyB64)
	if err != nil {
		return nil, err
	}
	if !attest.IsValidPublicKey(pub) {
		return nil, errInvalidPeerKey
	}
	return pub, nil
}

func parsePeerPubB64ToRaw(s string) (ed25519.PublicKey, error) {
	pub, err := decodeValidPeerKey(s)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX: %w", err)
	}
	ed, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ed25519 public key")
	}
	return ed, nil
}

func decodeTokenList(data []byte) [][]byte {
	if len(data) < 4 {
		return nil
	}
	count := int(binary.BigEndian.Uint32(data[:4]))
	if count == 0 || len(data) < 4+count*storage.ElemSize {
		return nil
	}
	tokens := make([][]byte, count)
	for i := range tokens {
		off := 4 + i*storage.ElemSize
		tokens[i] = data[off : off+storage.ElemSize]
	}
	return tokens
}
