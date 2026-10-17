package main

import (
	"context"
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
	app *App, rv func(context.Context, *storage.Storage, kamune.VerifyRequest) error,
	peer *storage.Peer,
) <-chan error {
	errCh := make(chan error, 1)
	store := app.store()
	go func() {
		errCh <- rv(context.Background(), store, kamune.VerifyRequest{Peer: peer})
	}()
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
		{name: "another peer's name with a ZWJ gets the pseudonym",
			mode: VerificationModeQuick, claimed: "Bob\u200d",
			other: "Bob", wantName: pseudo, wantSaved: true},
		{name: "another peer's name with a filler gets the pseudonym",
			mode: VerificationModeStrict, claimed: "Bob\u3164",
			other: "Bob", wantName: pseudo, wantSaved: true},
		{name: "no name gets the pseudonym",
			mode: VerificationModeStrict, claimed: "",
			wantName: pseudo, wantSaved: true},
		{name: "a blank name gets the pseudonym",
			mode: VerificationModeStrict, claimed: "\u3164",
			wantName: pseudo, wantSaved: true},
		{name: "another blank name gets the pseudonym",
			mode: VerificationModeQuick, claimed: "\u2800",
			other: "\u3164", wantName: pseudo, wantSaved: true},
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

// TestPromptsQueueUpToCap is kept as a name the old queue tests used.
// RFC007 §20.1 allows one open prompt: a second handshake is rejected
// with errVerifierBusy, including the user's own dials.
func TestPromptsQueueUpToCap(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()
	events := recordEvents(app)
	rv := app.verifierWithin(app.lifeCtx(), VerificationModeStrict, true)

	first := newTestPeer(t, "Alice")
	errCh := runVerifier(app, rv, first)
	ids := waitPending(t, app, 1)
	a.Equal(ids, events.promptIDs())
	a.Equal("Alice",
		events.named("verify-peer")[0][0].(map[string]any)["peerName"])

	extra := newTestPeer(t, "Alice")
	a.ErrorIs(waitVerdict(t, runVerifier(app, rv, extra)), errVerifierBusy)
	a.Equal(ids, pendingIDs(app), "a busy request must not replace one")
	a.Len(events.named("verify-peer"), 1)

	app.VerifyResponse(ids[0], false)
	a.ErrorIs(waitVerdict(t, errCh), kamune.ErrVerificationFailed)
	a.Equal(ids, events.closedIDs())
	a.Empty(pendingIDs(app))

	errCh = runVerifier(app, rv, extra)
	next := waitPending(t, app, 1)
	app.VerifyResponse(next[0], false)
	a.ErrorIs(waitVerdict(t, errCh), kamune.ErrVerificationFailed)
}

// TestOwnDialPromptsSkipInboundCap used to exempt the user's own dials
// from the inbound cap. RFC007 §20.1 has one open prompt for every
// handshake, so an outbound prompt is rejected while an inbound one is
// open.
func TestOwnDialPromptsSkipInboundCap(t *testing.T) {
	cases := []struct {
		name string
		mode VerificationMode
	}{
		{"strict", VerificationModeStrict},
		{"quick", VerificationModeQuick},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			app, cleanup := newTestAppWithStorage(t)
			defer cleanup()
			inbound := app.verifierWithin(app.lifeCtx(), tc.mode, true)
			outbound := app.verifierWithin(app.lifeCtx(), tc.mode, false)

			held := runVerifier(app, inbound, newTestPeer(t, "x"))
			ids := waitPending(t, app, 1)

			a.ErrorIs(waitVerdict(t,
				runVerifier(app, outbound, newTestPeer(t, "Bob"))),
				errVerifierBusy)

			app.VerifyResponse(ids[0], false)
			a.ErrorIs(waitVerdict(t, held), kamune.ErrVerificationFailed)
		})
	}
}

// TestInboundPromptsDoNotBlockOwnDial used to let a dial open a prompt
// while a Strict server already had one. RFC007 §20.1 rejects the dial
// with errVerifierBusy until the inbound prompt is answered.
func TestInboundPromptsDoNotBlockOwnDial(t *testing.T) {
	a := require.New(t)
	app, _ := newUnlockedApp(t, "secret")
	app.mu.Lock()
	app.verifMode = VerificationModeStrict
	app.mu.Unlock()
	addr := freeTCPAddr(t)
	_, _, err := app.StartServer(
		addr, "tcp", "", "alice", "", "", "", false, false, "",
	)
	a.NoError(err)
	t.Cleanup(func() { _ = app.StopServer() })

	store := openTestStorage(t)
	go func() {
		d, err := kamune.NewDialer(addr, store, acceptAll,
			kamune.DialWithTCP(), kamune.DialWithClientName("x"))
		if err != nil {
			return
		}
		if tr, err := d.Dial(); err == nil {
			_ = tr.Close()
		}
	}()
	inboundIDs := waitPending(t, app, 1)

	carol, carolKey := startTestServer(t, "Carol", readUntilEnd)
	res, err := app.ConnectToServer(
		carol, "tcp", "", "", "alice", "", "",
		fingerprint.Base64(carolKey), "", false, false, "",
	)
	a.Error(err)
	a.Empty(res.SessionID)
	a.Equal(inboundIDs, pendingIDs(app))
	app.VerifyResponse(inboundIDs[0], false)
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
	a.ErrorIs(err, kamune.ErrVerificationFailed)
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
		ids := waitPending(t, app, 1)
		a.ErrorIs(waitVerdict(t, runVerifier(app, rv, second)),
			errVerifierBusy)

		app.VerifyResponse(ids[0], false)
		waitVerdict(t, errFirst)
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
// peer's numeric code and not emoji or hex.
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
	a.Equal(fingerprint.Numeric(peer.PublicKey), data["peerCode"])
	_, hasEmoji := data["emoji"]
	_, hasHex := data["hex"]
	a.False(hasEmoji)
	a.False(hasHex)
	a.Equal(fingerprint.Numeric(peer.PublicKey),
		app.identifyPeer(app.store(), peer).Fingerprint)
}

func runVerifierReq(
	app *App, rv kamune.RemoteVerifier, req kamune.VerifyRequest,
) <-chan error {
	errCh := make(chan error, 1)
	store := app.store()
	go func() {
		errCh <- rv(context.Background(), store, req)
	}()
	return errCh
}

func policyReq(
	t *testing.T, app *App, role kamune.Role, known bool,
) kamune.VerifyRequest {
	t.Helper()
	peer := newTestPeer(t, "Bob")
	if known {
		peer.FirstSeen = time.Now()
		require.New(t).NoError(app.store().StorePeer(peer))
	}
	local, err := app.store().PublicKey()
	require.New(t).NoError(err)
	return kamune.VerifyRequest{
		Peer:           peer,
		LocalPublicKey: local,
		Role:           role,
		SessionID:      "SIDTEST",
	}
}

func TestVerifierPolicyTable(t *testing.T) {
	tests := []struct {
		name          string
		mode          VerificationMode
		role          kamune.Role
		known         bool
		pinned        bool
		resumeOffered bool
		resumed       bool
		wantPrompt    bool
	}{
		{
			name: "strict initiator", mode: VerificationModeStrict,
			role: kamune.RoleInitiator, wantPrompt: true,
		},
		{
			name: "strict initiator pinned resume",
			mode: VerificationModeStrict, role: kamune.RoleInitiator,
			pinned: true, resumeOffered: true, known: true,
		},
		{
			name: "strict responder", mode: VerificationModeStrict,
			role: kamune.RoleResponder, known: true, wantPrompt: true,
		},
		{
			name: "strict responder resumed", mode: VerificationModeStrict,
			role: kamune.RoleResponder, resumed: true, known: true,
			wantPrompt: true,
		},
		{
			name: "quick initiator pinned", mode: VerificationModeQuick,
			role: kamune.RoleInitiator, pinned: true, known: true,
		},
		{
			name: "quick initiator stored unpinned",
			mode: VerificationModeQuick, role: kamune.RoleInitiator,
			known: true, wantPrompt: true,
		},
		{
			name: "quick initiator unknown", mode: VerificationModeQuick,
			role: kamune.RoleInitiator, wantPrompt: true,
		},
		{
			name: "quick responder resumed", mode: VerificationModeQuick,
			role: kamune.RoleResponder, resumed: true, known: true,
		},
		{
			name: "quick responder pinned", mode: VerificationModeQuick,
			role: kamune.RoleResponder, pinned: true,
		},
		{
			name: "quick responder stored", mode: VerificationModeQuick,
			role: kamune.RoleResponder, known: true,
		},
		{
			name: "quick responder unknown", mode: VerificationModeQuick,
			role: kamune.RoleResponder, wantPrompt: true,
		},
		{
			name: "auto initiator", mode: VerificationModeAutoAccept,
			role: kamune.RoleInitiator,
		},
		{
			name: "auto responder", mode: VerificationModeAutoAccept,
			role: kamune.RoleResponder,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			app, cleanup := newTestAppWithStorage(t)
			defer cleanup()
			app.verifMode = tt.mode
			req := policyReq(t, app, tt.role, tt.known)
			req.Pinned = tt.pinned
			req.ResumeOffered = tt.resumeOffered
			req.Resumed = tt.resumed

			rv := app.verifierWithin(
				app.lifeCtx(), tt.mode, tt.role == kamune.RoleResponder,
			)
			errCh := runVerifierReq(app, rv, req)
			if !tt.wantPrompt {
				a.NoError(waitVerdict(t, errCh))
				a.Empty(pendingIDs(app))
				return
			}
			ids := waitPending(t, app, 1)
			app.VerifyResponse(ids[0], true)
			a.NoError(waitVerdict(t, errCh))
		})
	}
}

func TestStrictResponderPromptCarriesTwoCodes(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()
	app.verifMode = VerificationModeStrict
	events := recordEvents(app)
	req := policyReq(t, app, kamune.RoleResponder, true)
	req.Resumed = true
	req.SessionID = "SIDRESUME"

	errCh := runVerifierReq(app, app.verifierWithin(
		app.lifeCtx(), VerificationModeStrict, true,
	), req)
	ids := waitPending(t, app, 1)
	prompts := events.named("verify-peer")
	a.Len(prompts, 1)
	data := prompts[0][0].(map[string]any)
	a.Equal("responder", data["role"])
	a.Equal(req.Peer.Name, data["peerName"])
	a.Equal(true, data["resumed"])
	a.Equal("SIDRESUME", data["sessionID"])
	a.Equal(fingerprint.Numeric(req.LocalPublicKey), data["ownCode"])
	a.Equal(fingerprint.Numeric(req.Peer.PublicKey), data["peerCode"])
	a.Equal(
		fingerprint.SafetyNumber(req.LocalPublicKey, req.Peer.PublicKey),
		data["safetyNumber"],
	)
	_, hasEmoji := data["emoji"]
	_, hasHex := data["hex"]
	a.False(hasEmoji)
	a.False(hasHex)
	app.VerifyResponse(ids[0], true)
	a.NoError(waitVerdict(t, errCh))
}

func TestVerifierBusyRejectsSecondPrompt(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()
	app.verifMode = VerificationModeStrict
	first := policyReq(t, app, kamune.RoleResponder, false)
	second := policyReq(t, app, kamune.RoleInitiator, false)

	errCh := runVerifierReq(app, app.verifierWithin(
		app.lifeCtx(), VerificationModeStrict, true,
	), first)
	waitPending(t, app, 1)

	err := waitVerdict(t, runVerifierReq(app, app.verifierWithin(
		app.lifeCtx(), VerificationModeStrict, false,
	), second))
	a.ErrorIs(err, errVerifierBusy)
	a.Len(pendingIDs(app), 1)

	app.VerifyResponse(pendingIDs(app)[0], false)
	a.Error(waitVerdict(t, errCh))
}

func TestNameCollisionFlagsUnknownKey(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()
	app.verifMode = VerificationModeQuick
	events := recordEvents(app)
	a.NoError(app.store().StorePeer(&storage.Peer{
		Name: "Bob", PublicKey: newTestPubKey(t), FirstSeen: time.Now(),
	}))
	req := policyReq(t, app, kamune.RoleResponder, false)
	req.Peer.Name = "bob"

	errCh := runVerifierReq(app, app.verifierWithin(
		app.lifeCtx(), VerificationModeQuick, true,
	), req)
	ids := waitPending(t, app, 1)
	data := events.named("verify-peer")[0][0].(map[string]any)
	a.Equal(true, data["nameCollision"])
	a.Equal("Bob", data["storedName"])
	a.Equal("bob", data["peerName"])
	app.VerifyResponse(ids[0], false)
	a.Error(waitVerdict(t, errCh))
}

func TestInitiatorPromptHasEmptyPeerName(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()
	app.verifMode = VerificationModeStrict
	events := recordEvents(app)
	req := policyReq(t, app, kamune.RoleInitiator, false)
	req.Peer.Name = "should-not-show"

	errCh := runVerifierReq(app, app.getVerifier(), req)
	ids := waitPending(t, app, 1)
	data := events.named("verify-peer")[0][0].(map[string]any)
	a.Equal("initiator", data["role"])
	a.Equal("", data["peerName"])
	app.VerifyResponse(ids[0], false)
	a.Error(waitVerdict(t, errCh))
}

func TestDefaultFingerprintFormatIsNumeric(t *testing.T) {
	a := require.New(t)
	app := NewApp()
	a.Equal("numeric", app.fingerprintFmt)
}
