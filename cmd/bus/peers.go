package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
)

// PeerInfo is a view-model of a known peer. PublicKeyBase64 is the
// stable lookup key (and the user-facing form). FingerprintEmoji is
// the human-friendly derivation, both produced via the fingerprint
// package.
type PeerInfo struct {
	Name             string    `json:"name"`
	PublicKeyBase64  string    `json:"publicKeyBase64"`
	FirstSeen        time.Time `json:"firstSeen"`
	LastSeen         time.Time `json:"lastSeen"`
	FingerprintEmoji string    `json:"fingerprintEmoji"`
}

// ListKnownPeers returns all non-expired peers from the storage layer,
// sorted by most recent LastSeen first. The result is the current
// cache state, not a fresh DB read — call refreshPeersCache first if
// the caller needs the latest view.
func (a *App) ListKnownPeers() []PeerInfo {
	a.mu.RLock()
	out := make([]PeerInfo, len(a.peers))
	copy(out, a.peers)
	a.mu.RUnlock()
	return out
}

// GetPeer returns a single known peer by base64 public key. Returns
// an error if the peer is not in the cache (either unknown or
// expired and pruned by the storage layer).
func (a *App) GetPeer(publicKeyB64 string) (PeerInfo, error) {
	pub, err := decodePeerPubKey(publicKeyB64)
	if err != nil {
		return PeerInfo{}, err
	}

	a.mu.RLock()
	defer a.mu.RUnlock()
	for _, p := range a.peers {
		if peerKeyMatches(p, pub) {
			return p, nil
		}
	}
	return PeerInfo{}, fmt.Errorf("peer not found: %s", publicKeyB64)
}

// AddPeer inserts a peer manually. publicKeyB64 is the raw URL-safe
// base64 (no padding) of the ed25519 public key bytes — the same
// form returned by fingerprint.Base64. name is optional; when empty,
// the bus uses the fingerprint pseudonym. The new peer's FirstSeen
// and LastSeen are set to now.
func (a *App) AddPeer(publicKeyB64, name string) error {
	pub, err := decodePeerPubKey(publicKeyB64)
	if err != nil {
		return err
	}

	store := a.store()
	if store == nil {
		return errors.New("storage is not available")
	}

	if _, err := store.FindPeer(pub); err == nil {
		return fmt.Errorf("peer already exists: %s", publicKeyB64)
	}

	if name == "" {
		name = fingerprint.Pseudonym(pub)
	}

	now := time.Now()
	peer := &storage.Peer{
		Name:       name,
		PublicKey:  pub,
		FirstSeen:  now,
		LastSeen:   now,
		AppVersion: "",
	}
	if err := store.StorePeer(peer); err != nil {
		return fmt.Errorf("store peer: %w", err)
	}

	a.refreshPeersCache()
	a.addLogEntry("INFO", "Added peer: "+name)
	return nil
}

// DeletePeer removes a peer from the storage layer by base64 public
// key and refreshes the cache.
func (a *App) DeletePeer(publicKeyB64 string) error {
	pub, err := decodePeerPubKey(publicKeyB64)
	if err != nil {
		return err
	}

	store := a.store()
	if store == nil {
		return errors.New("storage is not available")
	}

	if err := store.DeletePeer(pub); err != nil {
		return fmt.Errorf("delete peer: %w", err)
	}

	a.refreshPeersCache()
	a.addLogEntry("INFO", "Deleted peer: "+publicKeyB64)
	return nil
}

// RenamePeer updates the display name of a known peer. The public
// key, timestamps, and storage identity are preserved; the
// underlying storage layer's AddEncrypted acts as an upsert on the
// same key.
func (a *App) RenamePeer(publicKeyB64, name string) error {
	pub, err := decodePeerPubKey(publicKeyB64)
	if err != nil {
		return err
	}

	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return errors.New("name is required")
	}

	store := a.store()
	if store == nil {
		return errors.New("storage is not available")
	}

	existing, err := store.FindPeer(pub)
	if err != nil {
		return fmt.Errorf("peer not found: %s", publicKeyB64)
	}

	existing.Name = trimmed
	if err := store.StorePeer(existing); err != nil {
		return fmt.Errorf("store peer: %w", err)
	}

	a.refreshPeersCache()
	a.addLogEntry("INFO", "Renamed peer to "+trimmed)
	return nil
}

// refreshPeersCache rebuilds the in-memory peer list from the storage
// layer. Called after any mutation path (AddPeer, DeletePeer,
// verifier-accept). Safe to call from any goroutine.
func (a *App) refreshPeersCache() {
	store := a.store()
	if store == nil {
		return
	}

	dbPeers, err := store.ListPeers()
	if err != nil {
		a.addLogEntry("WARN", "Failed to refresh peers cache: "+err.Error())
		return
	}

	infos := make([]PeerInfo, 0, len(dbPeers))
	for _, p := range dbPeers {
		infos = append(infos, peerToInfo(p))
	}
	sort.SliceStable(infos, func(i, j int) bool {
		if infos[i].LastSeen.Equal(infos[j].LastSeen) {
			return infos[i].Name < infos[j].Name
		}
		return infos[i].LastSeen.After(infos[j].LastSeen)
	})

	a.mu.Lock()
	a.peers = infos
	a.mu.Unlock()

	a.emitEvent("peers-updated")
}

// emitEvent is a defensive wrapper around runtime.EventsEmit that
// skips the call when the context is not a live Wails context
// (e.g. inside unit tests). The Wails runtime panics on a non-Wails
// context via log.Fatalf, which would terminate the test process.
func (a *App) emitEvent(eventName string, data ...interface{}) {
	if a.ctx == nil {
		return
	}
	if a.ctx.Value("events") == nil {
		return
	}
	runtime.EventsEmit(a.ctx, eventName, data...)
}

func peerToInfo(p *storage.Peer) PeerInfo {
	return PeerInfo{
		Name:             p.Name,
		PublicKeyBase64:  fingerprint.Base64(p.PublicKey),
		FirstSeen:        p.FirstSeen,
		LastSeen:         p.LastSeen,
		FingerprintEmoji: strings.Join(fingerprint.Emoji(p.PublicKey), " • "),
	}
}

func decodePeerPubKey(publicKeyB64 string) ([]byte, error) {
	cleaned := strings.TrimSpace(publicKeyB64)
	if cleaned == "" {
		return nil, errors.New("public key is required")
	}
	// Tolerate padded input (some tools emit standard base64) by
	// stripping it before passing to the strict RawURL decoder.
	cleaned = strings.TrimRight(cleaned, "=")
	pub, err := base64.RawURLEncoding.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("decode base64: %w", err)
	}
	// Storage enforces 44-byte PKIX; surface that error here
	// with a friendlier message instead of waiting for the
	// round trip to the store.
	if len(pub) != 44 {
		return nil, fmt.Errorf(
			"public key must be 44 bytes (PKIX), got %d", len(pub),
		)
	}
	return pub, nil
}

func peerKeyMatches(p PeerInfo, pub []byte) bool {
	return p.PublicKeyBase64 == fingerprint.Base64(pub)
}

// parsePeerPubB64ToRaw decodes a peer public key from base64 (PKIX form,
// 44 bytes) into a raw 32-byte ed25519.PublicKey. Used by TokenFromKeys
// and other relayconn helpers that need the raw key form.
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
