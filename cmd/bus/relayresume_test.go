package main

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
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
