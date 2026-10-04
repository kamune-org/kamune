package main

import (
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

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
	cases := []struct {
		name      string
		stored    string
		incognito bool
		wantName  string
		wantSaved bool
	}{
		{"unknown peer is saved", "", false, "carol", true},
		{"known peer keeps its name", "carol (work)", false,
			"carol (work)", true},
		{"incognito saves nothing", "", true, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			app, cleanup := newTestAppWithStorage(t)
			defer cleanup()
			app.incognito = tc.incognito
			store := app.store()

			peer := newTestPeer(t, "carol")
			if tc.stored != "" {
				a.NoError(store.StorePeer(&storage.Peer{
					Name: tc.stored, PublicKey: peer.PublicKey,
				}))
			}

			app.rememberPeer(store, peer)

			got, err := store.FindPeer(peer.PublicKey)
			if !tc.wantSaved {
				a.Error(err)
				return
			}
			a.NoError(err)
			a.Equal(tc.wantName, got.Name)
		})
	}
}
