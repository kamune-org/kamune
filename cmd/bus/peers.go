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

	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
)

// PeerInfo is a view-model of a known peer. PublicKeyBase64 is the
// stable lookup key (and the user-facing form). FingerprintNumeric is the
// fingerprint for people to compare and FingerprintEmoji a short visual
// one, all produced via the fingerprint package.
type PeerInfo struct {
	Name               string    `json:"name"`
	PublicKeyBase64    string    `json:"publicKeyBase64"`
	FirstSeen          time.Time `json:"firstSeen"`
	LastSeen           time.Time `json:"lastSeen"`
	FingerprintNumeric string    `json:"fingerprintNumeric"`
	FingerprintEmoji   string    `json:"fingerprintEmoji"`
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

// ErrInvalidPeerKey rejects a peer key that is not a usable Ed25519
// public key: one of small order, under which anyone can forge
// signatures, or a non-canonical encoding, which gives one key several
// IDs and fingerprints.
var ErrInvalidPeerKey = errors.New("not a valid Ed25519 public key")

// AddPeer inserts a peer manually. publicKeyB64 is the raw URL-safe
// base64 (no padding) of the ed25519 public key bytes — the same
// form returned by fingerprint.Base64. name is optional; when empty,
// the bus uses the fingerprint pseudonym. The new peer's FirstSeen
// and LastSeen are set to now. A key that attest.IsValidPublicKey
// rejects is refused with ErrInvalidPeerKey.
func (a *App) AddPeer(publicKeyB64, name string) error {
	pub, err := decodePeerPubKey(publicKeyB64)
	if err != nil {
		return err
	}
	if !attest.IsValidPublicKey(pub) {
		return ErrInvalidPeerKey
	}
	if strings.TrimSpace(name) != "" {
		if name, err = validateLabel(name); err != nil {
			return err
		}
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
// key and refreshes the cache. When the database cannot be compacted
// afterwards, the peer is deleted all the same and the user is warned;
// see deletedButNotCompacted.
func (a *App) DeletePeer(publicKeyB64 string) error {
	pub, err := decodePeerPubKey(publicKeyB64)
	if err != nil {
		return err
	}

	store := a.store()
	if store == nil {
		return errors.New("storage is not available")
	}

	// A failed compaction leaves the peer deleted all the same.
	err = store.DeletePeer(pub)
	if err != nil && !errors.Is(err, storage.ErrCompactFailed) {
		return fmt.Errorf("delete peer: %w", err)
	}

	a.refreshPeersCache()
	a.addLogEntry("INFO", "Deleted peer: "+publicKeyB64)
	if err != nil {
		a.deletedButNotCompacted(store, "The peer", err)
	}
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

	trimmed, err := validateLabel(name)
	if err != nil {
		return err
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

// rememberPeer saves the remote peer of a session that has just been
// established when its key is not stored yet, unless incognito, the mode
// the session started in, or the current incognito mode is on. mode is
// the verification mode whose verifier admitted the peer. The
// verifiers only decide whether to admit a peer; saving it here, after
// the handshake, keeps a peer whose handshake fails after the user
// accepted it from becoming a known peer.
//
// The stored name becomes the peer's label in every later session, so a
// claimed name is kept only when the user accepted the peer in a prompt
// that showed it, and only when no other stored peer has that name. A
// peer that Auto-Accept admitted, or that claims another peer's name or
// no name, is saved under the pseudonym of its key.
func (a *App) rememberPeer(
	store *storage.Storage, peer *storage.Peer, mode VerificationMode,
	incognito bool,
) {
	if store == nil || peer == nil || incognito || a.GetIncognito() {
		return
	}
	if _, err := store.FindPeer(peer.PublicKey); err == nil {
		return
	}

	name := strings.TrimSpace(peer.Name)
	prompted := mode != VerificationModeAutoAccept
	keyB64 := fingerprint.Base64(peer.PublicKey)
	if !prompted || name == "" || a.isOtherPeersName(keyB64, name) {
		name = fingerprint.Pseudonym(peer.PublicKey)
	}

	now := time.Now()
	if err := store.StorePeer(&storage.Peer{
		Name:       name,
		PublicKey:  peer.PublicKey,
		FirstSeen:  now,
		LastSeen:   now,
		AppVersion: peer.AppVersion,
	}); err != nil {
		a.addLogEntry("WARN", "Failed to save peer: "+err.Error())
		return
	}
	a.refreshPeersCache()
}

// refreshPeersCache rebuilds the in-memory peer list from the storage
// layer. Called after any mutation path (AddPeer, DeletePeer,
// rememberPeer). Safe to call from any goroutine.
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

func peerToInfo(p *storage.Peer) PeerInfo {
	return PeerInfo{
		Name:               sanitizeName(p.Name),
		PublicKeyBase64:    fingerprint.Base64(p.PublicKey),
		FirstSeen:          p.FirstSeen,
		LastSeen:           p.LastSeen,
		FingerprintNumeric: fingerprint.Numeric(p.PublicKey),
		FingerprintEmoji: strings.Join(
			fingerprint.Emoji(p.PublicKey), " • ",
		),
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
