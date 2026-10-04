package main

import (
	"bytes"
	"log/slog"
	"strings"
	"unicode"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"

	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
)

// nameKey returns the form in which the TUI compares peer names, so that
// names that read the same get the same key. It applies NFKC and case
// folding, drops the code points that show as nothing (see
// [isBlankInName]), and turns each run of white space into one space,
// with none at either end. A name that shows as nothing gets the empty
// key.
//
// Names that only look alike, such as one with a Latin "o" and one with
// a Cyrillic "о", keep different keys; only the fingerprint tells peers
// apart.
func nameKey(name string) string {
	s := norm.NFKC.String(sanitizeLine(name))
	s = norm.NFKC.String(cases.Fold().String(s))
	var b strings.Builder
	space := false
	for _, r := range s {
		switch {
		case unicode.IsSpace(r):
			space = b.Len() > 0
		case isBlankInName(r):
		default:
			if space {
				b.WriteByte(' ')
				space = false
			}
			b.WriteRune(r)
		}
	}
	return b.String()
}

// isBlankInName reports whether r shows as nothing, or as a blank that is
// not white space, in a name: a format character (ZWNJ and ZWJ among
// them), another default ignorable code point (the combining grapheme
// joiner and the Hangul fillers among them), a variation selector, or
// the blank Braille pattern U+2800.
func isBlankInName(r rune) bool {
	return r == '\u2800' || unicode.In(r,
		unicode.Cf,
		unicode.Other_Default_Ignorable_Code_Point,
		unicode.Variation_Selector,
	)
}

// otherPeerNames returns the [nameKey] of the name of every peer in store
// whose key is not key, apart from the empty key.
func otherPeerNames(
	store *storage.Storage, key []byte,
) (map[string]bool, error) {
	peers, err := store.ListPeers()
	if err != nil {
		return nil, err
	}
	names := make(map[string]bool, len(peers))
	for _, p := range peers {
		if k := nameKey(p.Name); k != "" && !bytes.Equal(p.PublicKey, key) {
			names[k] = true
		}
	}
	return names, nil
}

// newPeerName returns the name to store peer under, a peer whose key is
// not stored yet (see [nameToStore]).
func newPeerName(store *storage.Storage, peer *storage.Peer) string {
	others, err := otherPeerNames(store, peer.PublicKey)
	if err != nil {
		slog.Warn("could not read the stored peers", slog.Any("error", err))
	}
	return nameToStore(peer, others, err)
}

// nameToStore returns the name to store peer under, a peer whose key is
// not stored yet, given others and err, what [otherPeerNames] returned for
// it. The stored name labels the peer from then on, so it is the name the
// peer claimed only when that name shows as something and no other stored
// peer has a name that reads the same (see [nameKey]). Otherwise, and when
// the stored peers could not be read, it is the pseudonym of the peer's
// key.
func nameToStore(
	peer *storage.Peer, others map[string]bool, err error,
) string {
	if k := nameKey(peer.Name); err != nil || k == "" || others[k] {
		return fingerprint.Pseudonym(peer.PublicKey)
	}
	return peer.Name
}
