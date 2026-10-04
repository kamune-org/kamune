package main

import (
	"context"
	"encoding/hex"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/relayconn"
)

// newRelayTestApp returns an app with an open database that accepts
// every peer, and stops its server and sessions when the test ends.
func newRelayTestApp(t *testing.T) *App {
	t.Helper()
	app, cleanup := newTestAppWithStorage(t)
	t.Cleanup(cleanup)
	app.verifMode = VerificationModeAutoAccept
	t.Cleanup(func() {
		for _, s := range app.GetSessions() {
			_ = app.DisconnectSession(s.ID)
		}
		_ = app.StopServer()
	})
	return app
}

// startRelayTestServer starts a relay server on app at relay and returns
// the token the relay assigned at start.
func startRelayTestServer(t *testing.T, app *App, relay *fakeRelay) string {
	t.Helper()
	a := require.New(t)
	_, token, err := app.StartServer(
		"", "relay", relay.addr(), "srv", "", "", "", false, false, "",
	)
	a.NoError(err)
	return token
}

// waitRelayPool returns the relay reconnect tokens that app stores for
// session id once the two peers have exchanged them.
func waitRelayPool(t *testing.T, app *App, id string) [][]byte {
	t.Helper()
	a := require.New(t)
	var pool [][]byte
	a.Eventually(func() bool {
		pool = loadRelayPool(app.store(), id)
		return len(pool) > 0
	}, testWait, 10*time.Millisecond, "no relay pool for %s", id)
	return pool
}

// relayPair connects client to server through relay, on a relay token
// that server generated after it started, and returns the session ID and
// the token. Both sides hold the session's reconnect tokens.
func relayPair(
	t *testing.T, server, client *App, relay *fakeRelay,
) (string, string) {
	t.Helper()
	a := require.New(t)
	startRelayTestServer(t, server, relay)
	token, err := server.GenerateRelayToken("")
	a.NoError(err)
	res, err := client.ConnectToServer(
		"", "relay", relay.addr(), token, "cli", "", "", "", "",
		false, false,
	)
	a.NoError(err)
	waitRelayPool(t, server, res.SessionID)
	waitRelayPool(t, client, res.SessionID)
	return res.SessionID, token
}

// stopReconnect keeps app's dialed session id from reconnecting, so that
// the server's resume listeners wait for nobody.
func stopReconnect(t *testing.T, app *App, id string) {
	t.Helper()
	app.mu.RLock()
	var session *liveSession
	for _, s := range app.sessions {
		if s.ID == id {
			session = s
		}
	}
	app.mu.RUnlock()
	require.New(t).NotNil(session, "no session %s", id)
	session.reconnectCancel()
}

// TestRelayResumeListenerAdmitsOnlyItsSession checks that a resume
// listener turns away a fresh session from whoever else holds its token,
// such as the relay operator, and that the server then registers again
// for the dropped session's peer.
func TestRelayResumeListenerAdmitsOnlyItsSession(t *testing.T) {
	a := require.New(t)
	relay := newFakeRelay(t)
	server, client := newRelayTestApp(t), newRelayTestApp(t)
	intruder := newRelayTestApp(t)
	id, token := relayPair(t, server, client, relay)
	stopReconnect(t, client, id)
	registered := len(relay.created())

	relay.drop(token)
	resume := relay.waitCreated(t, registered+1)[registered]
	res, err := intruder.ConnectToServer(
		"", "relay", relay.addr(), resume, "intruder", "", "", "", "",
		false, false,
	)

	// The server closes the intruder's session and registers again.
	relay.waitCreated(t, registered+2)
	if err == nil {
		for _, s := range server.GetSessions() {
			a.NotEqual(res.SessionID, s.ID)
		}
	}
}

// TestRelaySessionOnGeneratedTokenResumes checks that a relay session on
// a token other than the startup one can resume after its connection
// drops: the server registers a listener with the session's first
// reconnect token, and the client reconnects through it.
func TestRelaySessionOnGeneratedTokenResumes(t *testing.T) {
	a := require.New(t)
	relay := newFakeRelay(t)
	server, client := newRelayTestApp(t), newRelayTestApp(t)
	events := recordEvents(client)
	id, token := relayPair(t, server, client, relay)
	pool := waitRelayPool(t, server, id)
	registered := len(relay.created())

	relay.drop(token)

	created := relay.waitCreated(t, registered+1)
	a.Equal(hex.EncodeToString(pool[0]), created[registered])
	a.Eventually(func() bool {
		return len(events.named("session-reconnected")) > 0
	}, testWait, 10*time.Millisecond)
}

// hexTokens returns tokens in hex.
func hexTokens(tokens [][]byte) []string {
	out := make([]string, len(tokens))
	for i, token := range tokens {
		out[i] = hex.EncodeToString(token)
	}
	return out
}

// waitPoolLen waits until app stores n relay reconnect tokens for
// session id.
func waitPoolLen(t *testing.T, app *App, id string, n int) {
	t.Helper()
	require.New(t).Eventually(func() bool {
		return len(loadRelayPool(app.store(), id)) == n
	}, testWait, 10*time.Millisecond)
}

// TestRelayResumeTokensAreSingleUse checks that a resume listener uses
// each reconnect token once: when it ends before the peer comes back,
// the next one has another token, and the used tokens are no longer
// stored.
func TestRelayResumeTokensAreSingleUse(t *testing.T) {
	a := require.New(t)
	relay := newFakeRelay(t)
	server, client := newRelayTestApp(t), newRelayTestApp(t)
	id, token := relayPair(t, server, client, relay)
	pool := hexTokens(waitRelayPool(t, server, id))
	stopReconnect(t, client, id)
	registered := len(relay.created())

	relay.drop(token)
	first := relay.waitCreated(t, registered+1)[registered]
	a.Contains(pool, first)
	relay.drop(first)
	second := relay.waitCreated(t, registered+2)[registered+1]
	a.Contains(pool, second)
	a.NotEqual(first, second)

	waitPoolLen(t, server, id, len(pool)-2)
	left := hexTokens(loadRelayPool(server.store(), id))
	a.NotContains(left, first)
	a.NotContains(left, second)
}

// TestRelayResumeStopsAfterWindow checks that once the resume window has
// passed, the server stops the live resume listener, registers no other
// and drops the session's reconnect tokens.
func TestRelayResumeStopsAfterWindow(t *testing.T) {
	a := require.New(t)
	relay := newFakeRelay(t)
	server, client := newRelayTestApp(t), newRelayTestApp(t)
	server.relayResumeWindow = time.Nanosecond
	id, token := relayPair(t, server, client, relay)
	stopReconnect(t, client, id)
	registered := len(relay.created())

	relay.drop(token)
	resume := relay.waitCreated(t, registered+1)[registered]

	// The resume ends once it has dropped the pool.
	waitPoolLen(t, server, id, 0)
	a.Eventually(func() bool {
		return !relayTokenListed(server, resume)
	}, testWait, 10*time.Millisecond, "the resume listener still runs")
	a.Len(relay.created(), registered+1)
}

// relayTokenListed reports whether app lists the relay token tok.
func relayTokenListed(app *App, tok string) bool {
	return slices.ContainsFunc(app.GetRelayTokens(),
		func(rt relayToken) bool { return rt.Token == tok })
}

// gateResumeWaits makes app's relay resumes report each wait between
// registrations on the returned channel, and wait until the test sends
// on proceed.
func gateResumeWaits(
	app *App,
) (waits <-chan time.Duration, proceed chan<- struct{}) {
	w := make(chan time.Duration)
	p := make(chan struct{})
	app.relayResumeWait = func(ctx context.Context, d time.Duration) bool {
		select {
		case w <- d:
		case <-ctx.Done():
			return false
		}
		select {
		case <-p:
			return true
		case <-ctx.Done():
			return false
		}
	}
	return w, p
}

// TestRelayResumeKeepsTokenOnFullRelay checks that while the relay turns
// away resume registrations, as a full relay does, the server keeps the
// reconnect tokens and registers the same one again after a wait that
// grows, however often it is turned away, and that the session resumes
// on that token once the relay takes registrations again.
func TestRelayResumeKeepsTokenOnFullRelay(t *testing.T) {
	a := require.New(t)
	relay := newFakeRelay(t)
	server, client := newRelayTestApp(t), newRelayTestApp(t)
	events := recordEvents(client)
	waits, proceed := gateResumeWaits(server)
	id, token := relayPair(t, server, client, relay)
	pool := len(waitRelayPool(t, server, id))
	registered := len(relay.created())
	relay.full.Store(true)

	relay.drop(token)
	var last time.Duration
	// Turned away more often than the pool has tokens.
	for turned := 1; turned <= pool+1; turned++ {
		var d time.Duration
		select {
		case d = <-waits:
		case <-time.After(testWait):
			t.Fatalf("no wait after %d turned away registrations", turned)
		}
		rejected := relay.rejected()
		a.Len(rejected, turned)
		a.Equal(rejected[0], rejected[turned-1], "a token was spent")
		a.Len(loadRelayPool(server.store(), id), pool)
		a.Greater(d, last)
		last = d
		if turned == pool+1 {
			relay.full.Store(false)
		}
		proceed <- struct{}{}
	}

	created := relay.waitCreated(t, registered+1)
	a.Equal(relay.rejected()[0], created[registered])
	a.Eventually(func() bool {
		return len(events.named("session-reconnected")) > 0
	}, testWait, 10*time.Millisecond)
}

// TestRelayResumeRenewsAfterLateFailedJoin checks that when a peer joins
// a resume listener but no session comes about, the server registers
// another one, even when the joined token has already left the token list
// as a used one.
func TestRelayResumeRenewsAfterLateFailedJoin(t *testing.T) {
	a := require.New(t)
	relay := newFakeRelay(t)
	server, client := newRelayTestApp(t), newRelayTestApp(t)
	id, token := relayPair(t, server, client, relay)
	stopReconnect(t, client, id)
	registered := len(relay.created())

	relay.drop(token)
	resume := relay.waitCreated(t, registered+1)[registered]
	a.Eventually(func() bool {
		return relayTokenListed(server, resume)
	}, testWait, 10*time.Millisecond)
	raw, err := hex.DecodeString(resume)
	a.NoError(err)
	conn, err := relayconn.DialRelayTCP(
		context.Background(), relay.ln.Addr().String(), raw,
	)
	a.NoError(err)
	// Open the handshake, so that the server accepts the conn, and then
	// stall it.
	_, err = exchange.Initiate(conn)
	a.NoError(err)
	// A used token leaves the list a few seconds after the join.
	a.Eventually(func() bool {
		return !relayTokenListed(server, resume)
	}, testWait, 50*time.Millisecond)

	// Only now does the handshake on the joined conn fail.
	a.NoError(conn.Close())
	relay.waitCreated(t, registered+2)
}

// TestRelayResumeEndsWithServer checks that stopping the server ends a
// resume and drops the session's reconnect tokens.
func TestRelayResumeEndsWithServer(t *testing.T) {
	a := require.New(t)
	relay := newFakeRelay(t)
	server, client := newRelayTestApp(t), newRelayTestApp(t)
	id, token := relayPair(t, server, client, relay)
	stopReconnect(t, client, id)
	registered := len(relay.created())

	relay.drop(token)
	relay.waitCreated(t, registered+1)
	a.NoError(server.StopServer())

	waitPoolLen(t, server, id, 0)
}

// TestStopServerWaitsForRelayResume checks that StopServer returns only
// once the relay resumes of its server have ended and dropped their
// sessions' reconnect tokens, so that nothing writes to the database
// after it returns, when it may be locked or switched.
func TestStopServerWaitsForRelayResume(t *testing.T) {
	a := require.New(t)
	relay := newFakeRelay(t)
	server, client := newRelayTestApp(t), newRelayTestApp(t)
	waiting := make(chan struct{}, 1)
	release := make(chan struct{})
	server.relayResumeWait = func(ctx context.Context, _ time.Duration) bool {
		select {
		case waiting <- struct{}{}:
		default:
		}
		<-ctx.Done()
		<-release
		return false
	}
	id, token := relayPair(t, server, client, relay)
	stopReconnect(t, client, id)
	relay.full.Store(true)
	relay.drop(token)
	select {
	case <-waiting:
	case <-time.After(testWait):
		t.Fatal("the relay resume did not start")
	}

	stopped := make(chan error, 1)
	go func() { stopped <- server.StopServer() }()
	select {
	case <-stopped:
		close(release)
		t.Fatal("StopServer returned while a relay resume still ran")
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-stopped:
		a.NoError(err)
	case <-time.After(testWait):
		t.Fatal("StopServer did not return")
	}
	a.Empty(loadRelayPool(server.store(), id))
}

// TestRemovedRelayResumeListenerIsNotRenewed checks that a resume
// listener whose token the user removes is not registered again, and
// that the session's reconnect tokens are dropped.
func TestRemovedRelayResumeListenerIsNotRenewed(t *testing.T) {
	a := require.New(t)
	relay := newFakeRelay(t)
	server, client := newRelayTestApp(t), newRelayTestApp(t)
	id, token := relayPair(t, server, client, relay)
	stopReconnect(t, client, id)
	registered := len(relay.created())

	relay.drop(token)
	resume := relay.waitCreated(t, registered+1)[registered]
	a.Eventually(func() bool {
		return slices.ContainsFunc(server.GetRelayTokens(),
			func(rt relayToken) bool { return rt.Token == resume })
	}, testWait, 10*time.Millisecond)
	a.NoError(server.RemoveRelayToken(resume))

	waitPoolLen(t, server, id, 0)
	a.Len(relay.created(), registered+1)
}

// TestClosedRelaySessionDropsReconnectTokens checks that a relay session
// that either side closes leaves no reconnect tokens on either side, and
// that the server registers no resume listener for it.
func TestClosedRelaySessionDropsReconnectTokens(t *testing.T) {
	for _, closer := range []string{"client", "server"} {
		t.Run(closer, func(t *testing.T) {
			a := require.New(t)
			relay := newFakeRelay(t)
			server, client := newRelayTestApp(t), newRelayTestApp(t)
			id, _ := relayPair(t, server, client, relay)
			registered := len(relay.created())

			app := client
			if closer == "server" {
				app = server
				a.Eventually(func() bool {
					return len(server.GetSessions()) == 1
				}, testWait, 10*time.Millisecond)
			}
			a.NoError(app.DisconnectSession(id))

			waitPoolLen(t, server, id, 0)
			waitPoolLen(t, client, id, 0)
			a.Eventually(func() bool {
				return len(server.GetSessions()) == 0 &&
					len(client.GetSessions()) == 0
			}, testWait, 10*time.Millisecond)
			a.Len(relay.created(), registered)
		})
	}
}

// TestShareInfoReusesRelayToken checks that opening the share card again
// shows the same relay token without registering another, and that a
// new one is made once that token is removed or used.
func TestShareInfoReusesRelayToken(t *testing.T) {
	a := require.New(t)
	relay := newFakeRelay(t)
	server := newRelayTestApp(t)
	startRelayTestServer(t, server, relay)

	first, err := server.GetShareInfo()
	a.NoError(err)
	again, err := server.GetShareInfo()
	a.NoError(err)
	a.Equal(first.RelayInfo.Token, again.RelayInfo.Token)
	a.Len(server.GetRelayTokens(), 2, "the startup and the card's token")

	a.NoError(server.RemoveRelayToken(first.RelayInfo.Token))
	fresh, err := server.GetShareInfo()
	a.NoError(err)
	a.NotEqual(first.RelayInfo.Token, fresh.RelayInfo.Token)

	server.markRelayTokenConsumed(fresh.RelayInfo.Token)
	next, err := server.GetShareInfo()
	a.NoError(err)
	a.NotEqual(fresh.RelayInfo.Token, next.RelayInfo.Token)
	relay.waitCreated(t, 4)
}

// TestShareInfoMakesOneTokenAtOnce checks that share cards opened at the
// same time get one relay token between them.
func TestShareInfoMakesOneTokenAtOnce(t *testing.T) {
	a := require.New(t)
	relay := newFakeRelay(t)
	server := newRelayTestApp(t)
	startRelayTestServer(t, server, relay)

	const cards = 4
	tokens := make([]string, cards)
	errs := make([]error, cards)
	var wg sync.WaitGroup
	for i := range cards {
		wg.Go(func() {
			info, err := server.GetShareInfo()
			errs[i] = err
			if err == nil {
				tokens[i] = info.RelayInfo.Token
			}
		})
	}
	wg.Wait()
	for i := range cards {
		a.NoError(errs[i])
		a.Equal(tokens[0], tokens[i])
	}
	a.Len(server.GetRelayTokens(), 2, "the startup and the card's token")
}

// stopCloseListener is a relay listener that records whether it was
// stopped or closed.
type stopCloseListener struct {
	stopped, closed atomic.Bool
}

func (l *stopCloseListener) Accept() (kamune.Conn, error) {
	return nil, net.ErrClosed
}

func (l *stopCloseListener) Close() error {
	l.closed.Store(true)
	return nil
}

func (l *stopCloseListener) Stop() { l.stopped.Store(true) }

// TestRemoveUsedRelayTokenKeepsSession checks that removing a relay token
// that a peer has just used, such as by regenerating the share card,
// stops its listener rather than closing it, which would end the peer's
// session.
func TestRemoveUsedRelayTokenKeepsSession(t *testing.T) {
	a := require.New(t)
	app := &App{}
	inner := &stopCloseListener{}
	tt := &tokenTracker{
		Listener: inner, token: "ab", app: app, dead: make(chan struct{}),
	}
	tt.consumed.Store(true)
	app.relayTokens = []relayToken{{Token: "ab", Consumed: true, listener: tt}}

	a.NoError(app.RemoveRelayToken("ab"))
	a.True(inner.stopped.Load())
	a.False(inner.closed.Load())
	a.Empty(app.GetRelayTokens())
}

// TestRelayTokenLogsNameOnlyAPrefix checks that the log names relay
// tokens by a short prefix, whether it reports them generated, shared,
// removed or expired.
func TestRelayTokenLogsNameOnlyAPrefix(t *testing.T) {
	a := require.New(t)
	relay := newFakeRelay(t)
	relay.ttl.Store(1)
	server := newRelayTestApp(t)
	events := recordEvents(server)
	first := startRelayTestServer(t, server, relay)
	generated, err := server.GenerateRelayToken("")
	a.NoError(err)
	card, err := server.GetShareInfo()
	a.NoError(err)
	a.NoError(server.RemoveRelayToken(generated))
	logs := func() []string {
		var out []string
		for _, d := range events.named("log-entry") {
			out = append(out, d[0].(LogEntryInfo).Message)
		}
		return out
	}
	a.Eventually(func() bool {
		return slices.ContainsFunc(logs(), func(msg string) bool {
			return strings.Contains(msg, "Relay token expired")
		})
	}, testWait, 10*time.Millisecond)

	for _, msg := range logs() {
		for _, tok := range []string{first, generated, card.RelayInfo.Token} {
			a.NotContains(msg, tok)
		}
	}
}
