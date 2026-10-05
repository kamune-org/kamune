package main

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
)

func TestIdentifyPeer(t *testing.T) {
	cases := []struct {
		name         string
		claimed      string
		stored       string
		other        string
		wantLabel    string
		wantKnown    bool
		wantMismatch bool
		wantConflict bool
		// noClaim is set when the claim reads as nothing, which
		// identifyPeer reports as no claim.
		noClaim bool
	}{
		{name: "known peer under its own name",
			claimed: "Bob", stored: "Bob",
			wantLabel: "Bob", wantKnown: true},
		{name: "known peer claiming another contact's name",
			claimed: "Bob", stored: "Mallory", other: "Bob",
			wantLabel: "Mallory", wantKnown: true,
			wantMismatch: true, wantConflict: true},
		{name: "known peer under a local nickname",
			claimed: "Robert", stored: "Bob from work",
			wantLabel: "Bob from work", wantKnown: true,
			wantMismatch: true},
		{name: "unknown peer is not labelled by its claim",
			claimed: "Bob", wantLabel: "<unknown>"},
		{name: "unknown peer claiming a contact's name",
			claimed: "bob", other: "Bob",
			wantLabel: "<unknown>", wantConflict: true},
		{name: "unknown peer claiming a contact's name with a ZWJ",
			claimed: "Bob\u200d", other: "Bob",
			wantLabel: "<unknown>", wantConflict: true},
		{name: "unknown peer claiming a contact's name with a filler",
			claimed: "Bob\u3164", other: "Bob",
			wantLabel: "<unknown>", wantConflict: true},
		{name: "known peer stored under a look-alike name",
			claimed: "Bob\u200d", stored: "Bob\u200d", other: "Bob",
			wantLabel: "Bob\u200d", wantKnown: true, wantConflict: true},
		{name: "known peer whose claim differs only by a ZWJ",
			claimed: "Bob\u200d", stored: "Bob",
			wantLabel: "Bob", wantKnown: true},
		{name: "unknown peer claiming a blank name",
			claimed: "\u3164", wantLabel: "<unknown>", noClaim: true},
		{name: "known peer stored under a blank name",
			claimed: "Bob", stored: "\u2800", wantLabel: "<pseudonym>",
			wantKnown: true, wantMismatch: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			app, cleanup := newTestAppWithStorage(t)
			defer cleanup()
			store := app.store()

			peer := newTestPeer(t, tc.claimed)
			if tc.stored != "" {
				a.NoError(store.StorePeer(&storage.Peer{
					Name: tc.stored, PublicKey: peer.PublicKey,
				}))
			}
			if tc.other != "" {
				a.NoError(store.StorePeer(&storage.Peer{
					Name: tc.other, PublicKey: newTestPubKey(t),
				}))
			}
			app.refreshPeersCache()

			id := app.identifyPeer(store, peer)

			want := tc.wantLabel
			switch want {
			case "<unknown>":
				want = unknownPeerLabel(peer.PublicKey)
				a.NotContains(want, tc.claimed)
			case "<pseudonym>":
				want = fingerprint.Pseudonym(peer.PublicKey)
			}
			// Names are shown sanitized: a code point that shows nothing
			// shows as U+FFFD.
			a.Equal(kamune.SanitizePeerName(want), id.Label)
			wantClaimed := tc.claimed
			if tc.noClaim {
				wantClaimed = ""
			}
			a.Equal(kamune.SanitizePeerName(wantClaimed), id.ClaimedName)
			a.NoError(kamune.ValidatePeerName(id.Label))
			a.NoError(kamune.ValidatePeerName(id.ClaimedName))
			a.Equal(tc.wantKnown, id.Known)
			a.Equal(tc.wantMismatch, id.NameMismatch)
			a.Equal(tc.wantConflict, id.NameConflict)
			a.Equal(fingerprint.Base64(peer.PublicKey), id.KeyB64)
		})
	}
}

// TestSameNameIgnoresInvisibleCodePoints checks that names which read
// the same compare equal, however they are spelled, and that names which
// read differently do not.
func TestSameNameIgnoresInvisibleCodePoints(t *testing.T) {
	cases := []struct {
		name string
		x, y string
		same bool
	}{
		{"identical", "Bob", "Bob", true},
		{"case", "Bob", "bOB", true},
		{"surrounding space", " Bob ", "Bob", true},
		{"inner space runs", "Bob  Smith", "Bob Smith", true},
		{"zero width joiner", "Bob\u200d", "Bob", true},
		{"zero width non-joiner inside", "B\u200cob", "Bob", true},
		{"zero width space", "\u200bBob", "Bob", true},
		{"word joiner", "Bo\u2060b", "Bob", true},
		{"soft hyphen", "Bo\u00adb", "Bob", true},
		{"hangul filler", "Bob\u3164", "Bob", true},
		{"halfwidth hangul filler", "Bob\uffa0", "Bob", true},
		{"hangul choseong filler", "\u115fBob", "Bob", true},
		{"braille blank", "Bob\u2800", "Bob", true},
		{"combining grapheme joiner", "Bo\u034fb", "Bob", true},
		{"variation selector", "Bob\ufe0f", "Bob", true},
		{"ideographic space", "Bob\u3000Smith", "Bob Smith", true},
		{"no-break space", "Bob\u00a0Smith", "Bob Smith", true},
		{"full-width letters", "\uff22\uff4f\uff42", "Bob", true},
		{"styled letters", "\U0001d401\U0001d428\U0001d41b", "Bob", true},
		{"composed and decomposed", "Jos\u00e9", "Jose\u0301", true},
		{"full case folding", "Stra\u00dfe", "STRASSE", true},
		{"other name", "Bob", "Bobby", false},
		{"space inside a name", "Bob", "B ob", false},
		{"accent", "Jos\u00e9", "Jose", false},
		{"invisible only", "\u200d\u3164", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			a.Equal(tc.same, sameName(tc.x, tc.y))
			a.Equal(tc.same, sameName(tc.y, tc.x))
		})
	}
}

// TestIsOtherPeersNameSeesLookAlikes checks that a name which reads as a
// stored contact's name counts as that contact's, so a new key cannot
// pass the name-conflict check by adding invisible code points, and that
// a name that reads as nothing matches no contact.
func TestIsOtherPeersNameSeesLookAlikes(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()
	bob := newTestPubKey(t)
	a.NoError(app.store().StorePeer(&storage.Peer{
		Name: "Bob", PublicKey: bob,
	}))
	app.refreshPeersCache()

	other := fingerprint.Base64(newTestPubKey(t))
	for _, claim := range []string{
		"Bob", "bob", "Bob\u200d", "Bob\u3164", "B\u00adob", "\uff22ob",
	} {
		a.True(app.isOtherPeersName(other, claim), "%q", claim)
	}
	a.False(app.isOtherPeersName(fingerprint.Base64(bob), "Bob\u200d"),
		"a peer's own name is not another peer's")
	a.False(app.isOtherPeersName(other, "Bobby"))
	a.False(app.isOtherPeersName(other, "\u200d\u3164"))
}

func TestUnknownPeerLabel(t *testing.T) {
	a := require.New(t)
	key := newTestPubKey(t)
	label := unknownPeerLabel(key)
	a.Regexp(`^Unknown peer \d{5} \d{5}$`, label)
	a.Equal(label, unknownPeerLabel(key))
	a.NotEqual(label, unknownPeerLabel(newTestPubKey(t)))
}

// TestQuickVerifierAdmitsKnownKeyUnderStoredName checks that a stored peer
// that introduces itself under another contact's name is admitted under
// its own stored name, and that its session is labelled with it.
func TestQuickVerifierAdmitsKnownKeyUnderStoredName(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()
	app.verifMode = VerificationModeQuick
	store := app.store()

	mallory := newTestPeer(t, "Bob")
	a.NoError(store.StorePeer(&storage.Peer{
		Name: "Mallory", PublicKey: mallory.PublicKey,
	}))
	a.NoError(store.StorePeer(&storage.Peer{
		Name: "Bob", PublicKey: newTestPubKey(t),
	}))
	app.refreshPeersCache()

	a.NoError(waitVerdict(t, runVerifier(app, app.getVerifier(), mallory)))
	a.Empty(pendingIDs(app))

	s := &liveSession{
		ID:       "s1",
		Identity: app.identifyPeer(store, mallory),
	}
	s.PeerName = s.Identity.Label
	info := s.info()
	a.Equal("Mallory", info.PeerName)
	a.Equal("Bob", info.ClaimedName)
	a.True(info.KnownPeer)
	a.True(info.NameMismatch)
	a.True(info.NameConflict)
}
