package main

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune"
)

// stalledListener accepts connections and never answers on them. It
// reports each connection it accepts on accepted.
func stalledListener(t *testing.T) (string, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.New(t).NoError(err)
	accepted := make(chan struct{}, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
			accepted <- struct{}{}
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String(), accepted
}

// TestCancelConnect cancels a connect that waits on the user to verify
// the server, on a server that does not answer, and on a relay that does
// not answer, and checks that it ends at once without a session.
func TestCancelConnect(t *testing.T) {
	cases := []struct {
		name string
		// start returns the connect arguments: transport, address and
		// relay address, and a channel that is ready once the connect
		// waits.
		start func(t *testing.T, app *App) (string, string, string, func())
	}{
		{"verification prompt", func(
			t *testing.T, app *App,
		) (string, string, string, func()) {
			addr, _ := startTestServer(t, "srv", readUntilEnd)
			return "tcp", addr, "", func() { waitPending(t, app, 1) }
		}},
		{"stalled server", func(
			t *testing.T, _ *App,
		) (string, string, string, func()) {
			addr, accepted := stalledListener(t)
			return "tcp", addr, "", func() { waitAccepted(t, accepted) }
		}},
		{"stalled relay", func(
			t *testing.T, _ *App,
		) (string, string, string, func()) {
			addr, accepted := stalledListener(t)
			return "relay", "", "tcp://" + addr,
				func() { waitAccepted(t, accepted) }
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			app, _ := newUnlockedApp(t, "secret")
			app.mu.Lock()
			app.verifMode = VerificationModeStrict
			app.mu.Unlock()
			transport, addr, relayAddr, waiting := tc.start(t, app)

			done := startConnect(app, transport, addr, relayAddr, "one")
			waiting()

			app.CancelConnect("one")
			waitCancelled(t, done)
			a.Empty(app.GetSessions())
			a.Empty(pendingIDs(app), "the prompt must close")
			app.mu.RLock()
			a.Empty(app.dialAttempts)
			app.mu.RUnlock()
		})
	}
}

type connectResult struct {
	res ConnectResult
	err error
}

// startConnect runs ConnectToServer with the attempt ID id, for a server
// at addr or a relay at relayAddr, and reports its result on the channel
// it returns.
func startConnect(
	app *App, transport, addr, relayAddr, id string,
) <-chan connectResult {
	done := make(chan connectResult, 1)
	go func() {
		res, err := app.ConnectToServer(
			addr, transport, relayAddr,
			"00112233445566778899aabbccddeeff", "", "", "", "", "",
			false, false, id,
		)
		done <- connectResult{res, err}
	}()
	return done
}

// waitCancelled waits for the result of a cancelled connect.
func waitCancelled(t *testing.T, done <-chan connectResult) {
	t.Helper()
	a := require.New(t)
	// Well below the handshake and verification timeouts, which would
	// end the connect as well.
	const cancelWait = 10 * time.Second
	select {
	case r := <-done:
		a.NoError(r.err)
		a.Equal(errCodeCancelled, r.res.ErrorCode)
	case <-time.After(cancelWait):
		t.Fatal("the cancelled connect did not end")
	}
}

// dialAttemptByID returns the dial attempt in progress with the attempt
// ID id, or nil.
func dialAttemptByID(app *App, id string) *dialAttempt {
	app.mu.RLock()
	defer app.mu.RUnlock()
	for d := range app.dialAttempts {
		if d.id == id {
			return d
		}
	}
	return nil
}

// TestCancelConnectSparesOtherAttempts cancels one of two connects in
// progress, as when the user starts a connect while a cancelled one is
// still ending, and checks that the other goes on.
func TestCancelConnectSparesOtherAttempts(t *testing.T) {
	a := require.New(t)
	app, _ := newUnlockedApp(t, "secret")
	oldAddr, oldAccepted := stalledListener(t)
	newAddr, newAccepted := stalledListener(t)
	oldDone := startConnect(app, "tcp", oldAddr, "", "old")
	waitAccepted(t, oldAccepted)
	newDone := startConnect(app, "tcp", newAddr, "", "new")
	waitAccepted(t, newAccepted)

	app.CancelConnect("old")
	waitCancelled(t, oldDone)
	d := dialAttemptByID(app, "new")
	a.NotNil(d, "the other connect must go on")
	a.NoError(d.ctx.Err(), "the other connect must not be cancelled")

	app.CancelConnect("new")
	waitCancelled(t, newDone)
}

// TestCancelConnectBeforeItBegins cancels a connect whose call has not
// reached the app yet, and checks that it ends at once when it does.
func TestCancelConnectBeforeItBegins(t *testing.T) {
	a := require.New(t)
	app, _ := newUnlockedApp(t, "secret")
	addr, _ := stalledListener(t)

	app.CancelConnect("early")
	waitCancelled(t, startConnect(app, "tcp", addr, "", "early"))
	app.mu.RLock()
	a.Empty(app.dialAttempts)
	a.Empty(app.earlyCancels, "the ID is used up")
	app.mu.RUnlock()

	// A connect with another ID is not cancelled.
	done := startConnect(app, "tcp", addr, "", "later")
	a.Eventually(func() bool {
		return dialAttemptByID(app, "later") != nil
	}, testWait, 10*time.Millisecond)
	a.NoError(dialAttemptByID(app, "later").ctx.Err())
	app.CancelConnect("later")
	waitCancelled(t, done)
}

// TestCancelConnectKeepsFewEarlyIDs checks that CancelConnect keeps only
// the newest IDs of the calls that it did not find.
func TestCancelConnectKeepsFewEarlyIDs(t *testing.T) {
	a := require.New(t)
	app := NewApp()
	const n = maxEarlyCancels + 5
	for i := range n {
		app.CancelConnect(strconv.Itoa(i))
	}
	app.CancelConnect(strconv.Itoa(n - 1))
	app.CancelConnect("")
	a.Len(app.earlyCancels, maxEarlyCancels)
	a.Equal(strconv.Itoa(n-maxEarlyCancels), app.earlyCancels[0])
	a.Equal(strconv.Itoa(n-1), app.earlyCancels[maxEarlyCancels-1])
}

func waitAccepted(t *testing.T, accepted <-chan struct{}) {
	t.Helper()
	select {
	case <-accepted:
	case <-time.After(testWait):
		t.Fatal("the connect did not reach the listener")
	}
}

// TestConnectedSessionOutlivesItsDial checks that the connection of an
// established session stays open once ConnectToServer has returned and
// its dial attempt has ended.
func TestConnectedSessionOutlivesItsDial(t *testing.T) {
	a := require.New(t)
	app, _ := newUnlockedApp(t, "secret")
	app.mu.Lock()
	app.verifMode = VerificationModeAutoAccept
	app.mu.Unlock()
	got := make(chan string, 1)
	addr, _ := startTestServer(t, "srv", func(tr *kamune.Transport) error {
		got <- receiveChat(t, tr)
		return readUntilEnd(tr)
	})

	res, err := app.ConnectToServer(
		addr, "tcp", "", "", "", "", "", "", "", false, false, "attempt",
	)
	a.NoError(err)
	a.Empty(res.ErrorCode)
	app.CancelConnect("attempt")

	a.NoError(app.SendMessage(res.SessionID, "hello"))
	select {
	case text := <-got:
		a.Equal("hello", text)
	case <-time.After(testWait):
		t.Fatal("the message did not arrive")
	}
	a.Len(app.GetSessions(), 1)
}
