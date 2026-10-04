package main

import (
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune"
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

// eventLog records the events an App emits.
type eventLog struct {
	mu     sync.Mutex
	events []recordedEvent
}

type recordedEvent struct {
	name string
	data []any
}

func recordEvents(app *App) *eventLog {
	l := &eventLog{}
	app.onEvent = func(name string, data ...any) {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.events = append(l.events, recordedEvent{name, data})
	}
	return l
}

// named returns the data of every event called name, in order.
func (l *eventLog) named(name string) [][]any {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out [][]any
	for _, e := range l.events {
		if e.name == name {
			out = append(out, e.data)
		}
	}
	return out
}

// promptIDs returns the request IDs of the verify-peer events, in order.
func (l *eventLog) promptIDs() []int64 {
	var ids []int64
	for _, d := range l.named("verify-peer") {
		ids = append(ids, d[0].(map[string]any)["requestID"].(int64))
	}
	return ids
}

// closedIDs returns the request IDs of the verify-peer-closed events.
func (l *eventLog) closedIDs() []int64 {
	var ids []int64
	for _, d := range l.named("verify-peer-closed") {
		ids = append(ids, d[0].(int64))
	}
	return ids
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

// TestPromptsQueueUpToCap checks that each prompt is a request of its own,
// that an answer reaches only the request it names, and that a peer
// arriving while maxPendingVerifications prompts wait is rejected without
// a prompt instead of replacing one.
func TestPromptsQueueUpToCap(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()
	app.verifMode = VerificationModeStrict
	events := recordEvents(app)
	rv := app.getVerifier()

	var errChs []<-chan error
	var peers []*storage.Peer
	for i := range maxPendingVerifications {
		p := newTestPeer(t, "Alice")
		peers = append(peers, p)
		errChs = append(errChs, runVerifier(app, rv, p))
		waitPending(t, app, i+1)
	}
	ids := pendingIDs(app)
	a.Equal(ids, events.promptIDs())
	for i, d := range events.named("verify-peer") {
		a.Equal(unknownPeerLabel(peers[i].PublicKey),
			d[0].(map[string]any)["peerName"])
	}

	extra := newTestPeer(t, "Alice")
	a.ErrorIs(waitVerdict(t, runVerifier(app, rv, extra)),
		ErrTooManyVerifications)
	a.Equal(ids, pendingIDs(app), "a capped request must not replace one")
	a.Len(events.named("verify-peer"), maxPendingVerifications)

	app.VerifyResponse(ids[1], false)
	a.ErrorIs(waitVerdict(t, errChs[1]), kamune.ErrVerificationFailed)
	a.Equal([]int64{ids[0], ids[2]}, pendingIDs(app))

	app.VerifyResponse(ids[0], true)
	a.NoError(waitVerdict(t, errChs[0]))
	app.VerifyResponse(ids[2], true)
	a.NoError(waitVerdict(t, errChs[2]))

	a.ElementsMatch(ids, events.closedIDs())
	a.Empty(pendingIDs(app))

	// With the queue drained, a new peer is prompted for again.
	errCh := runVerifier(app, rv, extra)
	next := waitPending(t, app, 1)
	app.VerifyResponse(next[0], false)
	a.ErrorIs(waitVerdict(t, errCh), kamune.ErrVerificationFailed)
}

func TestPromptTimeoutClosesRequest(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()
	app.verifMode = VerificationModeQuick
	app.verifTimeout = 10 * time.Millisecond
	events := recordEvents(app)

	err := waitVerdict(t,
		runVerifier(app, app.getVerifier(), newTestPeer(t, "Alice")))
	a.Error(err)
	a.Empty(pendingIDs(app))
	a.Len(events.promptIDs(), 1)
	a.Equal(events.promptIDs(), events.closedIDs())
}
