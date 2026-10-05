package main

import (
	"fmt"
	"strings"
	"unicode"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"

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
// using the peer store and the cached peer list. A name that reads as
// nothing, whose nameSkeleton is empty, counts as no name, whether the
// peer claims it or it is stored for the key.
func (a *App) identifyPeer(
	store *storage.Storage, peer *storage.Peer,
) peerIdentity {
	id := peerIdentity{
		KeyB64:      fingerprint.Base64(peer.PublicKey),
		Fingerprint: fingerprint.Numeric(peer.PublicKey),
	}
	// Names are compared as they are and only shown sanitized:
	// sanitizing turns a code point that shows nothing into a visible
	// U+FFFD, after which nameSkeleton could no longer tell that "Bob"
	// with a hidden suffix reads as "Bob".
	claimed := peer.Name
	if nameSkeleton(claimed) == "" {
		claimed = ""
	}
	id.ClaimedName = sanitizeName(claimed)
	var label string
	if store != nil {
		if stored, err := store.FindPeer(peer.PublicKey); err == nil {
			id.Known = true
			label = stored.Name
		}
	}
	if nameSkeleton(label) == "" {
		if id.Known {
			label = fingerprint.Pseudonym(peer.PublicKey)
		} else {
			label = unknownPeerLabel(peer.PublicKey)
		}
	}
	id.Label = sanitizeName(label)
	id.NameMismatch = id.Known && !sameName(label, claimed)
	id.NameConflict = a.isOtherPeersName(id.KeyB64, claimed) ||
		(id.Known && a.isOtherPeersName(id.KeyB64, label))
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

// sameName reports whether two peer names read the same: whether their
// nameSkeleton forms are equal.
func sameName(x, y string) bool {
	return nameSkeleton(x) == nameSkeleton(y)
}

// nameSkeleton returns the form of name that the name-conflict checks
// compare, so that a peer cannot claim a contact's name by adding code
// points that show as nothing, or by spelling it with others that read
// the same. kamune.ValidatePeerName lets some invisible code points
// through, such as U+200D ZERO WIDTH JOINER, which names in some scripts
// need, and U+3164 HANGUL FILLER, which shows as a blank.
//
// The skeleton drops every code point that blankRune reports, applies
// Unicode compatibility normalization (NFKC), which maps look-alikes
// such as full-width or styled letters to the plain ones, folds case,
// and collapses each run of white space into one space, with none at
// either end. The checks only compare skeletons; names are stored and
// shown as they are.
func nameSkeleton(name string) string {
	s := norm.NFKC.String(dropBlankRunes(name))
	s = norm.NFKC.String(cases.Fold().String(s))
	return strings.Join(strings.Fields(dropBlankRunes(s)), " ")
}

// dropBlankRunes returns s without the code points that blankRune
// reports.
func dropBlankRunes(s string) string {
	return strings.Map(func(r rune) rune {
		if blankRune(r) {
			return -1
		}
		return r
	}, s)
}

// blankRune reports whether r shows as nothing, or as a blank that is
// not white space: a control or format character (Cf, which holds the
// zero-width joiners and spaces and the bidirectional controls), a
// variation selector, another default-ignorable code point, such as
// U+034F COMBINING GRAPHEME JOINER and the Hangul fillers U+115F, U+1160,
// U+3164 and U+FFA0, or a code point drawn blank: U+2800 BRAILLE PATTERN
// BLANK, U+16FE4 KHITAN FILLER, U+1D159 MUSICAL SYMBOL NULL NOTEHEAD and
// U+FFFC OBJECT REPLACEMENT CHARACTER.
func blankRune(r rune) bool {
	switch r {
	case '\u2800', '\U00016FE4', '\U0001D159', '\uFFFC':
		return true
	}
	return unicode.IsControl(r) ||
		unicode.In(r, unicode.Cf, unicode.Variation_Selector,
			unicode.Other_Default_Ignorable_Code_Point)
}

// isOtherPeersName reports whether name reads the same as the stored name
// of a peer whose key is not keyB64; see sameName. A name that reads as
// nothing matches no peer.
func (a *App) isOtherPeersName(keyB64, name string) bool {
	skeleton := nameSkeleton(name)
	if skeleton == "" {
		return false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	for _, p := range a.peers {
		if p.PublicKeyBase64 != keyB64 && nameSkeleton(p.Name) == skeleton {
			return true
		}
	}
	return false
}
