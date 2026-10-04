package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/relayconn"
	relaybroker "github.com/kamune-org/kamune/pkg/relayconn/broker"
	"github.com/kamune-org/kamune/pkg/storage"
)

const (
	p2pTokenRefreshInterval = 30 * time.Second
	// defaultMatchTimeout bounds how long a p2p dial waits for the
	// broker to match its token with the server's.
	defaultMatchTimeout = 30 * time.Second
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
	Token      string             `json:"token"`
	Consumed   bool               `json:"consumed"`
	TTL        time.Duration      `json:"ttl_ns"`
	ExpiresAt  time.Time          `json:"expires_at"`
	Mode       string             `json:"mode"`
	PeerPubB64 string             `json:"peer_pub_b64,omitempty"`
	brokerAddr string             `json:"-"`
	ctx        context.Context    `json:"-"`
	cancel     context.CancelFunc `json:"-"`
	// broker is the broker identity that runP2PRefresh registers the
	// token under, or nil for a token that the p2p listener registers.
	broker *relaybroker.Client `json:"-"`
	// release, if set, releases broker once runP2PRefresh ends.
	release func() `json:"-"`
}

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

func (d *Daemon) GenerateP2PToken(
	brokerAddr, peerPubB64 string,
) (string, error) {
	if brokerAddr == "" {
		return "", errors.New("broker address is required")
	}

	staticToken, err := d.deriveP2PToken(peerPubB64)
	if err != nil {
		return "", err
	}

	expectedToken := ""
	if staticToken != nil {
		expectedToken = hex.EncodeToString(staticToken)
	}
	d.mu.RLock()
	listener := d.p2pListener
	var existingToken string
	for i := range d.p2pTokens {
		t := d.p2pTokens[i]
		if t.brokerAddr != brokerAddr {
			continue
		}
		if staticToken != nil && t.PeerPubB64 == peerPubB64 {
			existingToken = t.Token
			break
		}
		if staticToken == nil && t.Mode != "static" {
			existingToken = t.Token
			break
		}
	}
	d.mu.RUnlock()
	if existingToken != "" {
		return existingToken, nil
	}

	if l, ok := listener.(*p2pListener); ok && staticToken != nil {
		if err := l.RegisterToken(staticToken); err != nil {
			return "", fmt.Errorf("register token on punch socket: %w", err)
		}
		hexToken := hex.EncodeToString(staticToken)
		ptCtx, ptCancel := context.WithCancel(d.ctx)
		d.mu.Lock()
		d.p2pTokens = append(d.p2pTokens, p2pToken{
			Token:      hexToken,
			Mode:       "static",
			PeerPubB64: peerPubB64,
			Consumed:   false,
			TTL:        p2pTokenRefreshInterval,
			ExpiresAt:  time.Now().Add(p2pTokenRefreshInterval),
			brokerAddr: brokerAddr,
			ctx:        ptCtx,
			cancel:     ptCancel,
		})
		snapshot := d.p2pTokensSnapshot()
		d.mu.Unlock()
		d.emit(EvtP2PTokens, "", MapA{"tokens": snapshot})
		return hexToken, nil
	}

	// A static token has the broker identity that BrokerClient keeps for
	// it, while it is registered and for brokerIDHold after. A random
	// one, which the broker assigns anew, gets a new identity.
	broker, err := d.getOrCreateBrokerClient()
	if err != nil {
		return "", fmt.Errorf("broker client: %w", err)
	}
	var client *relaybroker.Client
	release := func() {}
	if staticToken != nil {
		client, err = broker.identity(brokerAddr, staticToken)
		release = func() { broker.release(brokerAddr, staticToken) }
	} else {
		client, err = newBrokerIdentity(brokerAddr)
	}
	if err != nil {
		return "", fmt.Errorf("broker client: %w", err)
	}

	echoCtx, echoCancel := context.WithTimeout(d.ctx, 5*time.Second)
	claimIP, claimPort, err := client.Echo(echoCtx)
	echoCancel()
	if err != nil {
		release()
		return "", fmt.Errorf("broker echo: %w", err)
	}

	ctx, cancel := context.WithCancel(d.ctx)
	token, err := client.Register(ctx, staticToken, claimIP, claimPort)
	if err != nil {
		cancel()
		release()
		return "", fmt.Errorf("broker register: %w", err)
	}

	hexToken := hex.EncodeToString(token)
	if expectedToken != "" && hexToken != expectedToken {
		d.addLogEntry("WARN",
			"Broker assigned a different token than derived: "+
				hexToken+" (expected "+expectedToken+")")
	}
	mode := "random"
	if staticToken != nil {
		mode = "static"
	}
	pt := p2pToken{
		Token:      hexToken,
		Mode:       mode,
		PeerPubB64: peerPubB64,
		TTL:        p2pTokenRefreshInterval,
		ExpiresAt:  time.Now().Add(p2pTokenRefreshInterval),
		brokerAddr: brokerAddr,
		ctx:        ctx,
		cancel:     cancel,
		broker:     client,
		release:    release,
	}

	d.mu.Lock()
	d.p2pTokens = append(d.p2pTokens, pt)
	snapshot := d.p2pTokensSnapshot()
	d.mu.Unlock()

	d.emit(EvtP2PTokens, "", MapA{"tokens": snapshot})
	d.addLogEntry("INFO", "Generated p2p token: "+hexToken)
	go d.runP2PRefresh(pt)
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

	pt.cancel()
	unregisterP2PToken(listener, pt.Token)
	d.emit(EvtP2PTokens, "", MapA{"tokens": snapshot})
	d.addLogEntry("INFO", "Removed p2p token: "+token)
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

func (d *Daemon) runP2PRefresh(pt p2pToken) {
	if pt.release != nil {
		defer pt.release()
	}
	ticker := time.NewTicker(p2pTokenRefreshInterval)
	defer ticker.Stop()

	var expiryTimer *time.Timer
	scheduleExpiry := func() {
		if expiryTimer != nil {
			expiryTimer.Stop()
		}
		remaining := time.Until(pt.ExpiresAt)
		if remaining <= 0 {
			remaining = time.Second
		}
		expiryTimer = time.AfterFunc(remaining, func() {
			d.removeP2PTokenByValue(pt.Token)
		})
	}
	scheduleExpiry()
	defer func() {
		if expiryTimer != nil {
			expiryTimer.Stop()
		}
	}()

	for {
		select {
		case <-pt.ctx.Done():
			return
		case <-ticker.C:
			if !d.refreshP2PToken(pt) {
				d.removeP2PTokenByValue(pt.Token)
				return
			}
			d.mu.RLock()
			for _, t := range d.p2pTokens {
				if t.Token == pt.Token {
					pt.ExpiresAt = t.ExpiresAt
					break
				}
			}
			d.mu.RUnlock()
			scheduleExpiry()
		}
	}
}

func (d *Daemon) refreshP2PToken(pt p2pToken) bool {
	client := pt.broker
	if client == nil {
		d.addLogEntry("ERROR", "p2p token refresh: no broker identity")
		return false
	}
	tokenBytes, err := hex.DecodeString(pt.Token)
	if err != nil {
		d.addLogEntry("ERROR",
			"p2p token refresh: decode token: "+err.Error())
		return false
	}
	claimIP, claimPort, err := client.Echo(pt.ctx)
	if err != nil {
		d.addLogEntry("ERROR", "p2p token refresh: echo: "+err.Error())
		return false
	}
	if _, err := client.Register(pt.ctx, tokenBytes, claimIP, claimPort); err != nil {
		d.addLogEntry("ERROR",
			"p2p token refresh: register: "+err.Error())
		return false
	}
	d.mu.Lock()
	for i, t := range d.p2pTokens {
		if t.Token == pt.Token {
			d.p2pTokens[i].ExpiresAt = time.Now().Add(p2pTokenRefreshInterval)
			break
		}
	}
	snapshot := d.p2pTokensSnapshot()
	d.mu.Unlock()
	d.emit(EvtP2PTokens, "", MapA{"tokens": snapshot})
	return true
}

func (d *Daemon) removeP2PTokenByValue(token string) {
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
		return
	}
	pt := d.p2pTokens[idx]
	d.p2pTokens = append(d.p2pTokens[:idx], d.p2pTokens[idx+1:]...)
	snapshot := d.p2pTokensSnapshot()
	listener := d.p2pListener
	d.mu.Unlock()
	pt.cancel()
	unregisterP2PToken(listener, pt.Token)
	d.emit(EvtP2PTokens, "", MapA{"tokens": snapshot})
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
	for _, token := range tokens {
		if token.cancel != nil {
			token.cancel()
		}
	}
	if listener != nil || len(tokens) > 0 {
		d.emit(EvtP2PTokens, "", MapA{"tokens": []p2pToken{}})
	}
}

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

func peerKeyMatches(p PeerInfo, pub []byte) bool {
	return p.PublicKey == fingerprint.Base64(pub)
}

func parsePeerPubB64ToRaw(s string) (ed25519.PublicKey, error) {
	pub, err := decodePeerPubKey(s)
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
