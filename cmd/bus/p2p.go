package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/kamune-org/kamune/pkg/relayconn"
)

// p2pTokenRefreshInterval is how often the bus re-registers a p2p token on the
// broker to keep it alive. The broker's default TTL is 60s, so refresh at
// half that to leave margin.
const p2pTokenRefreshInterval = 30 * time.Second

// p2pToken is the bus-side view of a broker-registered signaling token. The
// broker assigns random 16-byte tokens; the bus stores them as hex for display
// and runs a refresh loop to keep the registration alive until RemoveP2PToken
// or StopServer cancels it.
type p2pToken struct {
	Token      string        `json:"token"`
	Consumed   bool          `json:"consumed"`
	TTL        time.Duration `json:"ttl"`
	ExpiresAt  time.Time     `json:"expiresAt"`
	brokerAddr string        `json:"-"`
	ctx        context.Context    `json:"-"`
	cancel     context.CancelFunc `json:"-"`
}

// GenerateP2PToken registers a token on the broker at brokerAddr and returns
// its hex representation. Two modes:
//
//   - Random (peerPubB64 == ""): the broker assigns a fresh random token.
//   - Static (peerPubB64 != ""): the token is derived locally via
//     relayconn.TokenFromKeys(myPub, peerPub) and registered with the
//     broker. Both peers compute the same token independently, so the
//     listener and the dialer meet on the same broker registration.
//
// The bus runs a refresh loop in the background; remove the token (or
// stop the server) to cancel the loop.
func (a *App) GenerateP2PToken(brokerAddr, peerPubB64 string) (string, error) {
	if a.brokerClient == nil {
		return "", errors.New("broker client is not initialized")
	}
	if brokerAddr == "" {
		return "", errors.New("broker address is required")
	}

	var staticToken []byte
	if peerPubB64 != "" {
		store := a.store()
		if store == nil {
			return "", errors.New("storage is not available")
		}
		myPubRaw, err := store.PublicKey()
		if err != nil {
			return "", fmt.Errorf("get identity: %w", err)
		}
		peerPubRaw, err := parsePeerPubB64ToRaw(peerPubB64)
		if err != nil {
			return "", err
		}
		t, err := relayconn.TokenFromKeys(myPubRaw, peerPubRaw)
		if err != nil {
			return "", fmt.Errorf("derive static token: %w", err)
		}
		staticToken = t
	}

	client, err := a.brokerClient.Client(brokerAddr)
	if err != nil {
		return "", fmt.Errorf("broker client: %w", err)
	}

	claimIP, claimPort, err := client.Echo(context.Background())
	if err != nil {
		return "", fmt.Errorf("broker echo: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	token, err := client.Register(ctx, staticToken, claimIP, claimPort)
	if err != nil {
		cancel()
		return "", fmt.Errorf("broker register: %w", err)
	}

	hexToken := hex.EncodeToString(token)
	pt := p2pToken{
		Token:      hexToken,
		TTL:        p2pTokenRefreshInterval,
		ExpiresAt:  time.Now().Add(p2pTokenRefreshInterval),
		brokerAddr: brokerAddr,
		ctx:        ctx,
		cancel:     cancel,
	}

	a.mu.Lock()
	a.p2pTokens = append(a.p2pTokens, pt)
	snapshot := a.p2pTokensSnapshot()
	a.mu.Unlock()

	a.emitEvent("p2p-tokens", snapshot)
	if staticToken != nil {
		a.addLogEntry("INFO", "Generated static p2p token: "+hexToken)
	} else {
		a.addLogEntry("INFO", "Generated p2p token: "+hexToken)
	}
	go a.runP2PRefresh(pt)
	return hexToken, nil
}

// RemoveP2PToken cancels the broker registration for the given token and
// removes it from the active list.
func (a *App) RemoveP2PToken(token string) error {
	a.mu.Lock()
	idx := -1
	for i, t := range a.p2pTokens {
		if t.Token == token {
			idx = i
			break
		}
	}
	if idx == -1 {
		a.mu.Unlock()
		return errors.New("token not found")
	}
	pt := a.p2pTokens[idx]
	a.p2pTokens = append(a.p2pTokens[:idx], a.p2pTokens[idx+1:]...)
	snapshot := a.p2pTokensSnapshot()
	a.mu.Unlock()

	pt.cancel()
	a.emitEvent("p2p-tokens", snapshot)
	a.addLogEntry("INFO", "Removed p2p token: "+token)
	return nil
}

// GetP2PTokens returns a defensive copy of the current p2p tokens for the
// frontend.
func (a *App) GetP2PTokens() []p2pToken {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.p2pTokensSnapshot()
}

// p2pTokensSnapshot returns a defensive copy of the current p2p tokens. The
// caller must hold a.mu (read or write).
func (a *App) p2pTokensSnapshot() []p2pToken {
	out := make([]p2pToken, len(a.p2pTokens))
	copy(out, a.p2pTokens)
	return out
}

// runP2PRefresh re-registers the token at p2pTokenRefreshInterval until the
// token's context is cancelled. On failure the token is removed and the loop
// exits.
func (a *App) runP2PRefresh(pt p2pToken) {
	ticker := time.NewTicker(p2pTokenRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-pt.ctx.Done():
			return
		case <-ticker.C:
			if !a.refreshP2PToken(pt) {
				a.removeP2PTokenByValue(pt.Token)
				return
			}
		}
	}
}

// refreshP2PToken re-registers the token on the broker and updates ExpiresAt.
// Returns false if the broker is unreachable.
func (a *App) refreshP2PToken(pt p2pToken) bool {
	client, err := a.brokerClient.Client(pt.brokerAddr)
	if err != nil {
		a.addLogEntry("ERROR",
			"p2p token refresh: broker client: "+err.Error())
		return false
	}
	tokenBytes, err := hex.DecodeString(pt.Token)
	if err != nil {
		a.addLogEntry("ERROR",
			"p2p token refresh: decode token: "+err.Error())
		return false
	}
	claimIP, claimPort, err := client.Echo(pt.ctx)
	if err != nil {
		a.addLogEntry("ERROR", "p2p token refresh: echo: "+err.Error())
		return false
	}
	if _, err := client.Register(pt.ctx, tokenBytes, claimIP, claimPort); err != nil {
		a.addLogEntry("ERROR",
			"p2p token refresh: register: "+err.Error())
		return false
	}
	a.mu.Lock()
	for i, t := range a.p2pTokens {
		if t.Token == pt.Token {
			a.p2pTokens[i].ExpiresAt = time.Now().Add(p2pTokenRefreshInterval)
			break
		}
	}
	snapshot := a.p2pTokensSnapshot()
	a.mu.Unlock()
	a.emitEvent("p2p-tokens", snapshot)
	return true
}

// removeP2PTokenByValue is the internal variant called when the refresh loop
// fails and we want to drop the token without logging "user removed".
func (a *App) removeP2PTokenByValue(token string) {
	a.mu.Lock()
	idx := -1
	for i, t := range a.p2pTokens {
		if t.Token == token {
			idx = i
			break
		}
	}
	if idx == -1 {
		a.mu.Unlock()
		return
	}
	pt := a.p2pTokens[idx]
	a.p2pTokens = append(a.p2pTokens[:idx], a.p2pTokens[idx+1:]...)
	snapshot := a.p2pTokensSnapshot()
	a.mu.Unlock()
	pt.cancel()
	a.emitEvent("p2p-tokens", snapshot)
}

// p2pDialer is the connect-side counterpart to a p2pToken. It represents
// a one-shot broker registration that lives only as long as the dialer is
// waiting for a match. It is not refreshed (the listener keeps the
// registration alive); once the caller cancels or the context is done,
// the dialer is forgotten.
type p2pDialer struct {
	brokerAddr string
	token      string
	cancel     context.CancelFunc
}

// RegisterP2PDialer registers as a dialer on the broker so the listener
// can find this peer. The token is resolved from one of two sources:
//
//   - peerPubB64 (preferred): derives the static token via
//     relayconn.TokenFromKeys. The listener must use the same derivation.
//   - tokenHex: the listener-shared hex token (random-token-via-broker
//     path, distributed out-of-band).
//
// Exactly one of the two must be non-empty. The returned token is what
// the broker will associate with this registration.
//
// Hole-punch + connect happens in a later increment; for now this method
// only registers and returns. The cancel func tears down the registration.
func (a *App) RegisterP2PDialer(
	brokerAddr, peerPubB64, tokenHex string,
) (string, context.CancelFunc, error) {
	if a.brokerClient == nil {
		return "", nil, errors.New("broker client is not initialized")
	}
	if brokerAddr == "" {
		return "", nil, errors.New("broker address is required")
	}
	if peerPubB64 == "" && tokenHex == "" {
		return "", nil, errors.New(
			"either peer or token is required to register on the broker")
	}
	if peerPubB64 != "" && tokenHex != "" {
		return "", nil, errors.New(
			"peer and token are mutually exclusive")
	}

	var token []byte
	if peerPubB64 != "" {
		store := a.store()
		if store == nil {
			return "", nil, errors.New("storage is not available")
		}
		myPubRaw, err := store.PublicKey()
		if err != nil {
			return "", nil, fmt.Errorf("get identity: %w", err)
		}
		peerPubRaw, err := parsePeerPubB64ToRaw(peerPubB64)
		if err != nil {
			return "", nil, err
		}
		t, err := relayconn.TokenFromKeys(myPubRaw, peerPubRaw)
		if err != nil {
			return "", nil, fmt.Errorf("derive static token: %w", err)
		}
		token = t
	} else {
		raw, err := hex.DecodeString(tokenHex)
		if err != nil {
			return "", nil, fmt.Errorf("decode token: %w", err)
		}
		token = raw
	}

	client, err := a.brokerClient.Client(brokerAddr)
	if err != nil {
		return "", nil, fmt.Errorf("broker client: %w", err)
	}

	claimIP, claimPort, err := client.Echo(context.Background())
	if err != nil {
		return "", nil, fmt.Errorf("broker echo: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	registered, err := client.Register(ctx, token, claimIP, claimPort)
	if err != nil {
		cancel()
		return "", nil, fmt.Errorf("broker register: %w", err)
	}

	hexToken := hex.EncodeToString(registered)
	a.addLogEntry("INFO", "Registered p2p dialer with token: "+hexToken)
	return hexToken, cancel, nil
}
