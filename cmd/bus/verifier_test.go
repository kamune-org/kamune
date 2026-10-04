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

			app.rememberPeer(store, peer, tc.mode, false)

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

func TestParseVerificationMode(t *testing.T) {
	cases := []struct {
		in   string
		want VerificationMode
		ok   bool
	}{
		{"0", VerificationModeStrict, true},
		{"1", VerificationModeQuick, true},
		{"2", VerificationModeAutoAccept, true},
		{"3", 0, false},
		{"-1", 0, false},
		{"7", 0, false},
		{"quick", 0, false},
		{"", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			a := require.New(t)
			got, ok := parseVerificationMode(tc.in)
			a.Equal(tc.ok, ok)
			if tc.ok {
				a.Equal(tc.want, got)
			}
		})
	}
}

// TestUnknownModeVerifiesStrictly checks that a mode outside the defined
// ones gets the strict verifier, which asks even about a stored peer,
// instead of falling through to Auto-Accept.
func TestUnknownModeVerifiesStrictly(t *testing.T) {
	cases := []struct {
		name   string
		mode   VerificationMode
		prompt bool
	}{
		{"strict", VerificationModeStrict, true},
		{"quick", VerificationModeQuick, false},
		{"auto-accept", VerificationModeAutoAccept, false},
		{"negative", -1, true},
		{"three", 3, true},
		{"large", 42, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			app, cleanup := newTestAppWithStorage(t)
			defer cleanup()
			peer := newTestPeer(t, "Bob")
			a.NoError(app.store().StorePeer(&storage.Peer{
				Name: "Bob", PublicKey: peer.PublicKey,
			}))

			errCh := runVerifier(app, app.verifierFor(tc.mode), peer)
			if tc.prompt {
				ids := waitPending(t, app, 1)
				app.VerifyResponse(ids[0], false)
				a.ErrorIs(waitVerdict(t, errCh), kamune.ErrVerificationFailed)
				return
			}
			a.NoError(waitVerdict(t, errCh))
			a.Empty(pendingIDs(app))
		})
	}
}

func TestSetVerificationModeRejectsUnknownMode(t *testing.T) {
	for _, mode := range []int{-1, 3, 7} {
		a := require.New(t)
		app, cleanup := newTestAppWithStorage(t)
		app.verifMode = VerificationModeQuick

		a.False(app.SetVerificationMode(mode), "mode %d", mode)
		a.Equal(int(VerificationModeQuick), app.GetVerificationMode())
		stored, _ := app.store().GetSettings("bus", "verification_mode")
		a.Empty(stored, "an unknown mode must not be stored")
		cleanup()
	}
}

func TestInitFromStorageUnknownModeIsStrict(t *testing.T) {
	cases := []struct {
		stored string
		want   VerificationMode
	}{
		{"1", VerificationModeQuick},
		{"2", VerificationModeAutoAccept},
		{"3", VerificationModeStrict},
		{"-1", VerificationModeStrict},
		{"auto", VerificationModeStrict},
	}
	for _, tc := range cases {
		t.Run(tc.stored, func(t *testing.T) {
			a := require.New(t)
			app, cleanup := newTestAppWithStorage(t)
			defer cleanup()
			app.verifMode = VerificationModeQuick
			_, err := app.store().PublicKey()
			a.NoError(err)
			a.NoError(app.store().SetSettings(
				"bus", "verification_mode", tc.stored,
			))

			app.initFromStorage()

			a.Equal(int(tc.want), app.GetVerificationMode())
		})
	}
}

func TestSetVerificationModeConfirmsAutoAccept(t *testing.T) {
	cases := []struct {
		name     string
		from     VerificationMode
		to       VerificationMode
		answer   bool
		wantAsk  bool
		wantMode VerificationMode
	}{
		{name: "declined", from: VerificationModeQuick,
			to: VerificationModeAutoAccept, wantAsk: true,
			wantMode: VerificationModeQuick},
		{name: "confirmed", from: VerificationModeStrict,
			to: VerificationModeAutoAccept, answer: true, wantAsk: true,
			wantMode: VerificationModeAutoAccept},
		{name: "strict needs no confirmation", from: VerificationModeQuick,
			to: VerificationModeStrict, wantMode: VerificationModeStrict},
		{name: "quick needs no confirmation",
			from: VerificationModeAutoAccept, to: VerificationModeQuick,
			wantMode: VerificationModeQuick},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			app, cleanup := newTestAppWithStorage(t)
			defer cleanup()
			app.verifMode = tc.from
			var asked []string
			app.confirmFn = func(title, message string) bool {
				asked = append(asked, message)
				return tc.answer
			}

			changed := app.SetVerificationMode(int(tc.to))

			a.Equal(tc.wantMode != tc.from, changed)
			a.Equal(int(tc.wantMode), app.GetVerificationMode())
			if !tc.wantAsk {
				a.Empty(asked)
				return
			}
			a.Len(asked, 1)
			a.Contains(asked[0], "without asking you to compare fingerprints")
		})
	}
}

// TestPromptRestoresStatus checks that the status shown before a prompt
// comes back however the prompt ends, and that it does not come back
// while another prompt is open or after something else changed it.
func TestPromptRestoresStatus(t *testing.T) {
	const serverMsg = "Server running on :4000"
	cases := []struct {
		name   string
		answer func(app *App, id int64)
	}{
		{"accepted", func(app *App, id int64) {
			app.VerifyResponse(id, true)
		}},
		{"rejected", func(app *App, id int64) {
			app.VerifyResponse(id, false)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			app, cleanup := newTestAppWithStorage(t)
			defer cleanup()
			app.verifMode = VerificationModeStrict
			app.setStatus(StatusConnected, serverMsg)

			errCh := runVerifier(app, app.getVerifier(), newTestPeer(t, "x"))
			ids := waitPending(t, app, 1)
			a.Equal(StatusVerifying, app.GetStatus().Status)

			tc.answer(app, ids[0])
			waitVerdict(t, errCh)
			a.Equal(StatusInfo{StatusConnected, serverMsg}, app.GetStatus())
		})
	}

	t.Run("timed out", func(t *testing.T) {
		a := require.New(t)
		app, cleanup := newTestAppWithStorage(t)
		defer cleanup()
		app.verifMode = VerificationModeStrict
		app.verifTimeout = 10 * time.Millisecond
		app.setStatus(StatusConnected, serverMsg)

		a.Error(waitVerdict(t,
			runVerifier(app, app.getVerifier(), newTestPeer(t, "x"))))
		a.Equal(StatusInfo{StatusConnected, serverMsg}, app.GetStatus())
	})

	t.Run("two prompts", func(t *testing.T) {
		a := require.New(t)
		app, cleanup := newTestAppWithStorage(t)
		defer cleanup()
		app.verifMode = VerificationModeStrict
		app.setStatus(StatusConnected, serverMsg)
		rv := app.getVerifier()

		first := newTestPeer(t, "x")
		second := newTestPeer(t, "y")
		errFirst := runVerifier(app, rv, first)
		waitPending(t, app, 1)
		errSecond := runVerifier(app, rv, second)
		ids := waitPending(t, app, 2)

		app.VerifyResponse(ids[0], false)
		waitVerdict(t, errFirst)
		a.Equal(StatusInfo{
			StatusVerifying,
			verifyingStatus(unknownPeerLabel(second.PublicKey)),
		}, app.GetStatus())

		app.VerifyResponse(ids[1], true)
		a.NoError(waitVerdict(t, errSecond))
		a.Equal(StatusInfo{StatusConnected, serverMsg}, app.GetStatus())
	})

	t.Run("newer status is kept", func(t *testing.T) {
		a := require.New(t)
		app, cleanup := newTestAppWithStorage(t)
		defer cleanup()
		app.verifMode = VerificationModeStrict
		app.setStatus(StatusConnecting, "Connecting to peer...")

		errCh := runVerifier(app, app.getVerifier(), newTestPeer(t, "x"))
		ids := waitPending(t, app, 1)
		app.setStatus(StatusError, "Connection failed")
		app.VerifyResponse(ids[0], false)
		waitVerdict(t, errCh)
		a.Equal(StatusInfo{StatusError, "Connection failed"}, app.GetStatus())
	})
}

// TestVerificationDecidesAdmission runs a strict-mode prompt end to end,
// for a peer the app dials and one that dials the app's server, and
// checks that the user's answer decides whether the session is
// established and the peer stored.
func TestVerificationDecidesAdmission(t *testing.T) {
	cases := []struct {
		name   string
		serve  bool
		accept bool
	}{
		{"dialed peer accepted", false, true},
		{"dialed peer rejected", false, false},
		{"serving peer accepted", true, true},
		{"serving peer rejected", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			app, _ := newUnlockedApp(t, "secret")
			app.mu.Lock()
			app.verifMode = VerificationModeStrict
			app.mu.Unlock()

			var peerKey []byte
			done := make(chan error, 1)
			if tc.serve {
				addr := freeTCPAddr(t)
				_, _, err := app.StartServer(
					addr, "tcp", "", "srv", "", "", "", false, false, "",
				)
				a.NoError(err)
				t.Cleanup(func() { _ = app.StopServer() })
				peerStore := openTestStorage(t)
				peerKey, err = peerStore.PublicKey()
				a.NoError(err)
				// The server listens once StartServer returns.
				d, err := kamune.NewDialer(
					addr, peerStore, acceptAll, kamune.DialWithTCP(),
				)
				a.NoError(err)
				go func() {
					tr, err := d.Dial()
					if err == nil {
						t.Cleanup(func() { _ = tr.Close() })
					}
					done <- err
				}()
			} else {
				var addr string
				addr, peerKey = startTestServer(t, "srv", readUntilEnd)
				go func() {
					_, err := app.ConnectToServer(
						addr, "tcp", "", "", "", "", "", "", "",
						false, false, "",
					)
					done <- err
				}()
			}

			ids := waitPending(t, app, 1)
			app.VerifyResponse(ids[0], tc.accept)
			err := waitVerdict(t, done)

			_, peerErr := app.store().FindPeer(peerKey)
			if !tc.accept {
				a.Error(err, "a rejected peer must not get a session")
				a.Empty(app.GetSessions())
				a.Error(peerErr, "a rejected peer must not be stored")
				return
			}
			a.NoError(err)
			a.Eventually(func() bool {
				return len(app.GetSessions()) == 1
			}, testWait, time.Millisecond)
			a.Eventually(func() bool {
				_, err := app.store().FindPeer(peerKey)
				return err == nil
			}, testWait, time.Millisecond, "an accepted peer is stored")
		})
	}
}

// TestVerifyResponseIgnoresStaleAnswers checks that an answer to a
// request that does not exist changes nothing, and that a second answer
// to a request cannot overturn the first.
func TestVerifyResponseIgnoresStaleAnswers(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()
	app.verifMode = VerificationModeStrict

	app.VerifyResponse(12345, true)
	a.Empty(pendingIDs(app))

	errCh := runVerifier(app, app.getVerifier(), newTestPeer(t, "x"))
	ids := waitPending(t, app, 1)
	app.VerifyResponse(ids[0]+1, true)
	a.Equal(ids, pendingIDs(app), "an answer for another request is ignored")

	app.VerifyResponse(ids[0], false)
	app.VerifyResponse(ids[0], true)
	a.ErrorIs(waitVerdict(t, errCh), kamune.ErrVerificationFailed)
	a.Empty(pendingIDs(app))

	// The request is gone, so a late answer reaches nothing.
	app.VerifyResponse(ids[0], true)
	a.Empty(pendingIDs(app))
}

// TestPromptShowsNumericFingerprint checks that a prompt carries the
// numeric fingerprint of the peer's key, the one people compare, next to
// the emoji and hex ones.
func TestPromptShowsNumericFingerprint(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()
	app.verifMode = VerificationModeStrict
	events := recordEvents(app)

	peer := newTestPeer(t, "x")
	errCh := runVerifier(app, app.getVerifier(), peer)
	ids := waitPending(t, app, 1)
	app.VerifyResponse(ids[0], false)
	waitVerdict(t, errCh)

	prompts := events.named("verify-peer")
	a.Len(prompts, 1)
	data := prompts[0][0].(map[string]any)
	a.Equal(fingerprint.Numeric(peer.PublicKey), data["numeric"])
	a.Equal(fingerprint.Hex(peer.PublicKey), data["hex"])
	a.NotEmpty(data["emoji"])
	a.Equal(fingerprint.Numeric(peer.PublicKey),
		app.identifyPeer(app.store(), peer).Fingerprint)
}
