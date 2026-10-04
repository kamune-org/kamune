package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"

	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/relayconn"
	relaybroker "github.com/kamune-org/kamune/pkg/relayconn/broker"
)

// ErrNoP2PServer is returned by GenerateP2PToken when no P2P server is
// running with the given broker: a token is only of use while a server
// registered on its punch socket answers the peers that match it.
var ErrNoP2PServer = errors.New(
	"start a P2P server with this broker before generating a token",
)

// maxP2PTokens is how many tokens a P2P server's listener registers at
// most, its own token included. The listener sends a REGISTER for each
// token every 30 s from its punch socket, and a broker by default takes
// 20 REGISTERs a minute from one IPv4 address and drops the rest without
// a reply. Eight tokens cost 16 a minute, which leaves room for the first
// REGISTER of a new token and for a dial from the same address.
const maxP2PTokens = 8

// ErrTooManyP2PTokens is returned by GenerateP2PToken when the P2P
// server's listener already registers maxP2PTokens tokens. More would
// exceed the broker's REGISTER quota, and the broker would drop the
// newest tokens without a word.
var ErrTooManyP2PTokens = fmt.Errorf(
	"a P2P server keeps at most %d tokens: remove one first",
	maxP2PTokens,
)

// p2pToken is the bus-side view of a token that the running P2P server's
// listener registers with the broker. It is listed until RemoveP2PToken
// removes it or the server stops.
type p2pToken struct {
	Token string `json:"token"`
	// Mode is "static" when derived from a peer public key, "random"
	// when it was generated at random. Used by the sidebar to group /
	// label entries distinctly.
	Mode string `json:"mode"`
	// PeerPubB64 is set when Mode == "static"; identifies the
	// peer this token was derived for (so the sidebar can show the
	// peer's name alongside the token).
	PeerPubB64 string `json:"peerPubB64,omitempty"`
}

// GenerateP2PToken has the running P2P server register one more token
// with the broker at brokerAddr and returns it in hex. The server's
// listener registers the token from its punch socket, the address the
// broker gives a matched peer to punch to, and keeps it registered until
// RemoveP2PToken removes it or the server stops. Two modes:
//
//   - Random (peerPubB64 == ""): a fresh random token on every call, for
//     whoever is given it. The listener cannot tell which token a peer
//     matched on, so while a random token is registered it admits any
//     peer, also on a server started with a static token.
//   - Static (peerPubB64 != ""): the token derived via
//     relayconn.TokenFromKeys(myPub, peerPub). Both peers compute it on
//     their own, and it admits only that peer. A second call for the
//     same peer returns the token already registered.
//
// It returns ErrNoP2PServer when no P2P server runs with that broker,
// and ErrTooManyP2PTokens when the server already has maxP2PTokens.
func (a *App) GenerateP2PToken(brokerAddr, peerPubB64 string) (string, error) {
	if brokerAddr == "" {
		return "", errors.New("broker address is required")
	}
	a.mu.RLock()
	l, _ := a.p2pListener.(*p2pListener)
	a.mu.RUnlock()
	if l == nil || l.brokerAddr != brokerAddr {
		return "", ErrNoP2PServer
	}

	staticToken, err := a.deriveP2PToken(peerPubB64)
	if err != nil {
		return "", err
	}
	token, mode := staticToken, "static"
	if staticToken == nil {
		token, mode = make([]byte, relaybroker.TokenSize), "random"
		if _, err := rand.Read(token); err != nil {
			return "", fmt.Errorf("generate token: %w", err)
		}
	}
	hexToken := hex.EncodeToString(token)
	if mode == "static" && a.hasP2PToken(hexToken) {
		return hexToken, nil
	}

	peerKey := staticPeerKey(peerPubB64, staticToken)
	if err := l.RegisterToken(token, peerKey); err != nil {
		if errors.Is(err, ErrTooManyP2PTokens) {
			return "", err
		}
		return "", fmt.Errorf("register token on punch socket: %w", err)
	}

	a.mu.Lock()
	if a.p2pListener != l {
		a.mu.Unlock()
		return "", errors.New("the server stopped while registering the token")
	}
	if !slices.ContainsFunc(a.p2pTokens, func(t p2pToken) bool {
		return t.Token == hexToken
	}) {
		a.p2pTokens = append(a.p2pTokens, p2pToken{
			Token: hexToken, Mode: mode, PeerPubB64: peerPubB64,
		})
	}
	snapshot := a.p2pTokensSnapshot()
	a.mu.Unlock()

	a.emitEvent("p2p-tokens", snapshot)
	a.addLogEntry("INFO", "Generated "+mode+" p2p token: "+hexToken)
	return hexToken, nil
}

// hasP2PToken reports whether the hex token is in the p2p token list.
func (a *App) hasP2PToken(hexToken string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return slices.ContainsFunc(a.p2pTokens, func(t p2pToken) bool {
		return t.Token == hexToken
	})
}

// deriveP2PToken returns a relay token for the given peer. It prefers
// ECDH-derived tokens stored in a previous session (after handshake), falling
// back to the static token derived from public keys. Returns nil for
// random-token mode (when peerPubB64 is empty).
func (a *App) deriveP2PToken(peerPubB64 string) ([]byte, error) {
	if peerPubB64 == "" {
		return nil, nil
	}
	store := a.store()
	if store == nil {
		return nil, errors.New("storage is not available")
	}

	// Derive deterministic static token from public keys.
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

// RemoveP2PToken removes the given token from the active list and has the
// P2P server's listener stop registering it with the broker. The broker
// forgets the token once its last registration expires. The listener
// turns the peer of a removed static token away only while no random
// token is registered, since a random token admits any peer; see
// p2pListener.admitsPeer.
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
	a.p2pTokens = append(a.p2pTokens[:idx], a.p2pTokens[idx+1:]...)
	snapshot := a.p2pTokensSnapshot()
	l, _ := a.p2pListener.(*p2pListener)
	a.mu.Unlock()

	// The server's listener must stop registering the token with the
	// broker, or whoever holds it can still find the server.
	if raw, err := hex.DecodeString(token); err == nil && l != nil {
		l.UnregisterToken(raw)
	}
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
