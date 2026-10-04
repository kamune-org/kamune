package main

import (
	"bytes"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
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
	others := otherPeersNames(store, peer.PublicKey)
	id.NameConflict = hasName(others, id.ClaimedName) ||
		id.Known && hasName(others, id.Label)
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

// nameRuneAllowed reports whether kamune.ValidatePeerName allows r.
func nameRuneAllowed(r rune) bool {
	switch {
	case r == '\u200c', r == '\u200d':
		return true
	case unicode.IsControl(r):
		return false
	default:
		return !unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp)
	}
}

// sanitizeName makes a stored name safe to show, for names stored before
// the protocol limited them. Every code point that
// kamune.ValidatePeerName rejects, and every invalid UTF-8 sequence,
// becomes U+FFFD, and a name longer than kamune.MaxPeerNameLength bytes
// is cut on a rune boundary and ends with an ellipsis. The result always
// passes kamune.ValidatePeerName.
func sanitizeName(name string) string {
	const ellipsis = "…"
	var b strings.Builder
	limit := kamune.MaxPeerNameLength
	for i, r := range name {
		if r == utf8.RuneError {
			if _, size := utf8.DecodeRuneInString(name[i:]); size == 1 {
				r = unicode.ReplacementChar
			}
		}
		if !nameRuneAllowed(r) {
			r = unicode.ReplacementChar
		}
		if b.Len()+utf8.RuneLen(r) > limit {
			out := b.String()
			for len(out)+len(ellipsis) > limit {
				_, size := utf8.DecodeLastRuneInString(out)
				out = out[:len(out)-size]
			}
			return out + ellipsis
		}
		b.WriteRune(r)
	}
	return b.String()
}
