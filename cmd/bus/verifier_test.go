package main

import (
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
)

// testWait bounds how long a test waits for a verifier goroutine. It only
// turns a hang into a failure, so it is generous.
const testWait = 30 * time.Second

func newTestPeer(t *testing.T, name string) *storage.Peer {
	t.Helper()
	return &storage.Peer{Name: name, PublicKey: newTestPubKey(t)}
}

// pendingIDs returns the IDs of the open verification requests, oldest
// first.
func pendingIDs(app *App) []int64 {
	app.verifMu.Lock()
	defer app.verifMu.Unlock()
	ids := make([]int64, 0, len(app.verifRequests))
	for id := range app.verifRequests {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

// waitPending waits until n verification requests are open and returns
// their IDs, oldest first.
func waitPending(t *testing.T, app *App, n int) []int64 {
	t.Helper()
	a := require.New(t)
	var ids []int64
	a.Eventually(func() bool {
		ids = pendingIDs(app)
		return len(ids) == n
	}, testWait, time.Millisecond)
	return ids
}

// runVerifier runs rv in a goroutine and returns its result channel.
func runVerifier(
	app *App, rv func(*storage.Storage, *storage.Peer) error,
	peer *storage.Peer,
) <-chan error {
	errCh := make(chan error, 1)
	store := app.store()
	go func() { errCh <- rv(store, peer) }()
	return errCh
}

func waitVerdict(t *testing.T, errCh <-chan error) error {
	t.Helper()
	select {
	case err := <-errCh:
		return err
	case <-time.After(testWait):
		require.New(t).FailNow("verifier did not return")
		return nil
	}
}

func TestVerifiersDoNotStorePeers(t *testing.T) {
	cases := []struct {
		name   string
		mode   VerificationMode
		prompt bool
	}{
		{"strict", VerificationModeStrict, true},
		{"quick", VerificationModeQuick, true},
		{"auto-accept", VerificationModeAutoAccept, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			app, cleanup := newTestAppWithStorage(t)
			defer cleanup()
			app.verifMode = tc.mode

			peer := newTestPeer(t, "carol")
			errCh := runVerifier(app, app.getVerifier(), peer)
			if tc.prompt {
				ids := waitPending(t, app, 1)
				app.VerifyResponse(ids[0], true)
			}
			a.NoError(waitVerdict(t, errCh))

			_, err := app.store().FindPeer(peer.PublicKey)
			a.Error(err, "a verifier must not store the peer")
		})
	}
}

func TestRememberPeer(t *testing.T) {
	const (
		claimed = "carol"
		pseudo  = "<pseudonym>"
	)
	cases := []struct {
		name      string
		mode      VerificationMode
		claimed   string
		stored    string
		other     string
		incognito bool
		wantName  string
		wantSaved bool
	}{
		{name: "accepted in a strict prompt",
			mode: VerificationModeStrict, claimed: claimed,
			wantName: claimed, wantSaved: true},
		{name: "accepted in a quick prompt",
			mode: VerificationModeQuick, claimed: claimed,
			wantName: claimed, wantSaved: true},
		{name: "auto-accepted gets its pseudonym",
			mode: VerificationModeAutoAccept, claimed: claimed,
			wantName: pseudo, wantSaved: true},
		{name: "known peer keeps its name",
			mode: VerificationModeQuick, claimed: claimed,
			stored: "carol (work)", wantName: "carol (work)",
			wantSaved: true},
		{name: "another peer's name gets the pseudonym",
			mode: VerificationModeQuick, claimed: "Bob", other: "bob",
			wantName: pseudo, wantSaved: true},
		{name: "no name gets the pseudonym",
			mode: VerificationModeStrict, claimed: "",
			wantName: pseudo, wantSaved: true},
		{name: "incognito saves nothing",
			mode: VerificationModeQuick, claimed: claimed,
			incognito: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			app, cleanup := newTestAppWithStorage(t)
			defer cleanup()
			app.incognito = tc.incognito
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

			app.rememberPeer(store, peer, tc.mode)

			got, err := store.FindPeer(peer.PublicKey)
			if !tc.wantSaved {
				a.Error(err)
				return
			}
			a.NoError(err)
			want := tc.wantName
			if want == pseudo {
				want = fingerprint.Pseudonym(peer.PublicKey)
			}
			a.Equal(want, got.Name)
		})
	}
}
