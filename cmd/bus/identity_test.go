package main

import (
	"testing"

	"github.com/stretchr/testify/require"

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
			if want == "<unknown>" {
				want = unknownPeerLabel(peer.PublicKey)
				a.NotContains(want, tc.claimed)
			}
			a.Equal(want, id.Label)
			a.Equal(tc.claimed, id.ClaimedName)
			a.Equal(tc.wantKnown, id.Known)
			a.Equal(tc.wantMismatch, id.NameMismatch)
			a.Equal(tc.wantConflict, id.NameConflict)
			a.Equal(fingerprint.Base64(peer.PublicKey), id.KeyB64)
		})
	}
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
