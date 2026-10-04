package main

import (
	"fmt"
	"strings"

	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
)

// peerIdentity is how the bus names the remote side of a session or of a
// verification request.
//
// A peer's introduction carries a name the peer chose for itself, which
// proves nothing: any peer can introduce itself as "Bob". Only the key is
// authenticated. Label therefore comes from the local peer store when the
// key is stored, and is derived from the key otherwise. The name the peer
// sent is kept apart in ClaimedName and is only ever shown as its claim.
type peerIdentity struct {
	// Label names the peer in the UI: the name stored for its key, or
	// unknownPeerLabel for a key that is not stored.
	Label string
	// ClaimedName is the name from the peer's introduction.
	ClaimedName string
	// KeyB64 is the peer's public key, as fingerprint.Base64 gives it.
	KeyB64 string
	// Fingerprint is the numeric fingerprint of the peer's key, the one
	// for people to compare; see fingerprint.Numeric.
	Fingerprint string
	// Known reports whether the key is in the peer store.
	Known bool
	// NameMismatch reports a known peer whose claimed name differs from
	// the name stored for its key.
	NameMismatch bool
	// NameConflict reports a peer that claims, or is stored under, the
	// name of another stored peer.
	NameConflict bool
}

// identifyPeer describes peer, whose key the handshake authenticated,
// using the peer store and the cached peer list.
func (a *App) identifyPeer(
	store *storage.Storage, peer *storage.Peer,
) peerIdentity {
	id := peerIdentity{
		ClaimedName: sanitizeName(peer.Name),
		KeyB64:      fingerprint.Base64(peer.PublicKey),
		Fingerprint: fingerprint.Numeric(peer.PublicKey),
	}
	if store != nil {
		if stored, err := store.FindPeer(peer.PublicKey); err == nil {
			id.Known = true
			id.Label = sanitizeName(stored.Name)
		}
	}
	if id.Label == "" {
		if id.Known {
			id.Label = fingerprint.Pseudonym(peer.PublicKey)
		} else {
			id.Label = unknownPeerLabel(peer.PublicKey)
		}
	}
	id.NameMismatch = id.Known && !sameName(id.Label, id.ClaimedName)
	id.NameConflict = a.isOtherPeersName(id.KeyB64, id.ClaimedName) ||
		(id.Known && a.isOtherPeersName(id.KeyB64, id.Label))
	return id
}

// logName names the peer in log entries: its label, followed by the name
// it claimed when that differs.
func (id peerIdentity) logName() string {
	if sameName(id.Label, id.ClaimedName) {
		return id.Label
	}
	return fmt.Sprintf("%s (introduced as %q)", id.Label, id.ClaimedName)
}

// unknownPeerLabel names a peer whose key is not stored. It is derived
// from the key so that the peer cannot choose it, and reads as unknown so
// that it is not mistaken for a contact.
func unknownPeerLabel(key []byte) string {
	const groups = 2 // "12345 67890"
	digits := fingerprint.Numeric(key)
	return "Unknown peer " + digits[:groups*6-1]
}

// sameName reports whether two peer names read the same, ignoring case
// and surrounding space.
func sameName(x, y string) bool {
	return strings.EqualFold(strings.TrimSpace(x), strings.TrimSpace(y))
}

// isOtherPeersName reports whether name is the stored name of a peer whose
// key is not keyB64.
func (a *App) isOtherPeersName(keyB64, name string) bool {
	if strings.TrimSpace(name) == "" {
		return false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	for _, p := range a.peers {
		if p.PublicKeyBase64 != keyB64 && sameName(p.Name, name) {
			return true
		}
	}
	return false
}
