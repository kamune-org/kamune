package main

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
)

// errPeerKeyMismatch rejects a peer whose key is not the key of the peer
// that a dial, or the token a session came in on, was made for.
var errPeerKeyMismatch = errors.New(
	"the peer's key is not the key of the peer this connection is for",
)

// peerIdentity is how the daemon names the remote side of a session or
// of a verify_peer prompt.
//
// A peer introduces itself with a name it chose, which proves nothing:
// any peer can say that it is "Bob". Only its key is authenticated.
// Label therefore comes from the peer store when the key is stored, and
// from the key otherwise. The name the peer sent is kept apart in
// ClaimedName, as its claim.
type peerIdentity struct {
	// Label names the peer: the name stored for its key, or
	// unknownPeerLabel for a key that is not stored.
	Label string
	// ClaimedName is the name the peer introduced itself with.
	ClaimedName string
	// KeyB64 is the peer's public key, as fingerprint.Base64 gives it.
	KeyB64 string
	// Numeric is the numeric fingerprint of the key, the one for people
	// to compare.
	Numeric string
	// Known reports whether the key is stored.
	Known bool
	// NameMismatch reports a stored peer whose claimed name is not the
	// name stored for its key.
	NameMismatch bool
	// NameConflict reports a peer that claims, or is stored under, the
	// name of another stored peer.
	NameConflict bool
}

// identifyPeer describes peer, whose key the handshake authenticated,
// from the peers in store, which may be nil.
func identifyPeer(store *storage.Storage, peer *storage.Peer) peerIdentity {
	id := peerIdentity{
		ClaimedName: sanitizeName(peer.Name),
		KeyB64:      fingerprint.Base64(peer.PublicKey),
		Numeric:     fingerprint.Numeric(peer.PublicKey),
	}
	// storedName is the name as stored. Names are compared as they are,
	// not sanitized: sanitizing turns a code point that shows nothing
	// into a visible U+FFFD, and sameName could then no longer tell that
	// "Bob" with a hidden suffix reads as "Bob".
	var storedName string
	if store != nil {
		if stored, err := store.FindPeer(peer.PublicKey); err == nil {
			id.Known = true
			storedName = stored.Name
			id.Label = sanitizeName(stored.Name)
		}
	}
	if id.Label == "" {
		if id.Known {
			id.Label = fingerprint.Pseudonym(peer.PublicKey)
		} else {
			id.Label = unknownPeerLabel(peer.PublicKey)
		}
		storedName = id.Label
	}
	id.NameMismatch = id.Known && !sameName(storedName, peer.Name)
	others := otherPeersNames(store, peer.PublicKey)
	id.NameConflict = hasName(others, peer.Name) ||
		id.Known && hasName(others, storedName)
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

// unknownPeerLabel names a peer whose key is not stored. It comes from
// the key, so the peer cannot choose it, and reads as unknown, so it is
// not taken for a contact's name.
func unknownPeerLabel(key []byte) string {
	const groups = 2 // "12345 67890"
	digits := fingerprint.Numeric(key)
	return "Unknown peer " + digits[:groups*6-1]
}

// otherPeersNames returns the names of the peers in store whose key is
// not key.
func otherPeersNames(store *storage.Storage, key []byte) []string {
	if store == nil {
		return nil
	}
	peers, err := store.ListPeers()
	if err != nil {
		return nil
	}
	var names []string
	for _, p := range peers {
		if !bytes.Equal(p.PublicKey, key) {
			names = append(names, p.Name)
		}
	}
	return names
}

// hasName reports whether names holds a name that reads as name; see
// sameName. An empty name matches none.
func hasName(names []string, name string) bool {
	if nameKey(name) == "" {
		return false
	}
	for _, n := range names {
		if sameName(n, name) {
			return true
		}
	}
	return false
}

// sameName reports whether two peer names read the same: they are equal
// once nameKey has dropped what does not show, ignoring case.
func sameName(x, y string) bool {
	return strings.EqualFold(nameKey(x), nameKey(y))
}

// nameKey returns name without the code points that do not show, such
// as zero-width joiners, fillers and variation selectors, with each run
// of white space as one space, and trimmed. kamune.ValidatePeerName
// allows some of them, so "Bob" followed by a zero-width joiner would
// otherwise pass for another name than "Bob".
func nameKey(name string) string {
	var b strings.Builder
	space := false
	for _, r := range name {
		switch {
		case invisibleRune(r):
			continue
		case unicode.IsSpace(r):
			space = b.Len() > 0
			continue
		}
		if space {
			b.WriteByte(' ')
			space = false
		}
		b.WriteRune(r)
	}
	return b.String()
}

// invisibleRune reports whether r shows nothing: a format character, a
// default-ignorable filler, a variation selector or a blank pattern.
func invisibleRune(r rune) bool {
	return r == '\u2800' || unicode.In(r,
		unicode.Cf,
		unicode.Other_Default_Ignorable_Code_Point,
		unicode.Variation_Selector,
	)
}

// sanitizeName makes a stored name safe to show, for names stored before
// the protocol limited them. It is kamune.SanitizePeerName: every code
// point that kamune.ValidatePeerName rejects, and every invalid UTF-8
// sequence, becomes U+FFFD, and a name longer than
// kamune.MaxPeerNameLength bytes is cut on a rune boundary and ends with
// an ellipsis. The result always passes kamune.ValidatePeerName.
func sanitizeName(name string) string {
	return kamune.SanitizePeerName(name)
}

// pinPeer returns a verifier that rejects a peer whose key is not want
// with errPeerKeyMismatch, before rv sees it: such a peer answered a
// connection made for another peer, so it is neither asked about nor
// admitted, whatever name it claims and whether or not it is stored. A
// nil want returns rv.
func (d *Daemon) pinPeer(
	want []byte, rv kamune.RemoteVerifier,
) kamune.RemoteVerifier {
	if want == nil {
		return rv
	}
	return func(store *storage.Storage, peer *storage.Peer) error {
		if !bytes.Equal(peer.PublicKey, want) {
			d.forgetAdmitted(peer.PublicKey)
			d.addLogEntry("WARN", "Rejected peer "+
				identifyPeer(store, peer).logName()+
				": its key is not the key of the peer that was dialed")
			return errPeerKeyMismatch
		}
		return rv(store, peer)
	}
}
