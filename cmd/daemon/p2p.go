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

	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/relayconn"
	"github.com/kamune-org/kamune/pkg/storage"
)

const p2pTokenRefreshInterval = 30 * time.Second

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
	brokerAddr string,
	peerPubB64 string,
) (string, error) {
	if brokerAddr == "" {
		return "", errors.New("broker address is required")
	}
	broker, err := d.getOrCreateBrokerClient()
	if err != nil {
		return "", fmt.Errorf("broker client: %w", err)
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
		if err := d.refreshBrokerRegistration(
			broker, brokerAddr, existingToken,
		); err != nil {
			d.addLogEntry("WARN",
				"Failed to refresh existing p2p token: "+err.Error())
		} else {
			d.mu.Lock()
			for i := range d.p2pTokens {
				if d.p2pTokens[i].Token == existingToken {
					d.p2pTokens[i].ExpiresAt = time.Now().Add(
						p2pTokenRefreshInterval,
					)
					break
				}
			}
			snapshot := d.p2pTokensSnapshot()
			d.mu.Unlock()
			d.emit(EvtP2PTokens, "", MapA{"tokens": snapshot})
			d.addLogEntry("INFO",
				"Refreshed p2p token lifetime: "+existingToken)
		}
		return existingToken, nil
	}

	client, err := broker.Client(brokerAddr)
	if err != nil {
		return "", fmt.Errorf("broker client: %w", err)
	}

	echoCtx, echoCancel := context.WithTimeout(d.ctx, 5*time.Second)
	claimIP, claimPort, err := client.Echo(echoCtx)
	echoCancel()
	if err != nil {
		return "", fmt.Errorf("broker echo: %w", err)
	}

	ctx, cancel := context.WithCancel(d.ctx)
	token, err := client.Register(ctx, staticToken, claimIP, claimPort)
	if err != nil {
		cancel()
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

func (d *Daemon) refreshBrokerRegistration(
	broker *BrokerClient,
	brokerAddr, hexToken string,
) error {
	client, err := broker.Client(brokerAddr)
	if err != nil {
		return fmt.Errorf("broker client: %w", err)
	}
	ctx, cancel := context.WithTimeout(d.ctx, 5*time.Second)
	defer cancel()
	claimIP, claimPort, err := client.Echo(ctx)
	if err != nil {
		return fmt.Errorf("broker echo: %w", err)
	}
	tokenBytes, err := hex.DecodeString(hexToken)
	if err != nil {
		return fmt.Errorf("decode token: %w", err)
	}
	if _, err := client.Register(ctx, tokenBytes, claimIP, claimPort); err != nil {
		return fmt.Errorf("broker register: %w", err)
	}
	return nil
}

func (d *Daemon) deriveP2PToken(peerPubB64 string) ([]byte, error) {
	if peerPubB64 == "" {
		return nil, nil
	}
	store := d.store()
	if store == nil {
		return nil, errors.New("storage is not available")
	}

	peerPubPKIX, err := decodePeerPubKey(peerPubB64)
	if err != nil {
		return nil, fmt.Errorf("decode peer public key: %w", err)
	}
	sessionID, err := store.FindSessionByPeer(peerPubPKIX)
	if err != nil {
		return nil, fmt.Errorf("find session by peer: %w", err)
	}
	if sessionID != "" {
		m, err := store.GetMeta(
			sessionID, storage.RelayTokensKey,
		)
		if err == nil && m.Value() != nil {
			if tokens := decodeTokenList(m.Value()); len(tokens) > 0 {
				return tokens[0], nil
			}
		}
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
	d.mu.Unlock()

	pt.cancel()
	d.emit(EvtP2PTokens, "", MapA{"tokens": snapshot})
	d.addLogEntry("INFO", "Removed p2p token: "+token)
	return nil
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
	d.mu.RLock()
	broker := d.brokerClient
	d.mu.RUnlock()
	if broker == nil {
		d.addLogEntry("ERROR",
			"p2p token refresh: broker client is not initialized")
		return false
	}
	client, err := broker.Client(pt.brokerAddr)
	if err != nil {
		d.addLogEntry("ERROR",
			"p2p token refresh: broker client: "+err.Error())
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
	d.mu.Unlock()
	pt.cancel()
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
