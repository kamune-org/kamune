package main

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// startRelayServer starts a relay server on d at relay and returns the
// startup token the relay assigned.
func startRelayServer(
	t *testing.T, d *Daemon, rec *eventRecorder, relay *fakeRelay,
) string {
	d.handleStartServer(Command{
		ID: "start",
		Params: mustJSON(StartServerParams{
			Transport: "relay", RelayAddr: relay.addr(),
		}),
	})
	rec.waitFor(t, isEvent(EvtServerStarted))
	return relay.waitCreated(t, 1)[0]
}

// generateRelayToken registers another relay token on d's relay server
// and returns it.
func generateRelayToken(
	t *testing.T, d *Daemon, rec *eventRecorder, id ID,
) string {
	a := require.New(t)
	d.handleGenerateRelayToken(Command{ID: id})
	evt := rec.waitFor(t, func(e recordedEvent) bool { return e.ID == id })
	a.Equal(EvtResponse, evt.Evt, "generate failed: %v", evt.Data)
	token, _ := evt.Data["token"].(string)
	a.NotEmpty(token)
	return token
}

// dialRelay dials token at relay from d and returns the session's ID.
func dialRelay(
	t *testing.T, d *Daemon, rec *eventRecorder, relay *fakeRelay,
	token string,
) string {
	a := require.New(t)
	d.handleDial(Command{
		ID: "dial",
		Params: mustJSON(DialParams{
			Transport: "relay", RelayAddr: relay.addr(), Token: token,
		}),
	})
	evt := rec.waitFor(t, func(e recordedEvent) bool {
		return e.ID == "dial" &&
			(e.Evt == EvtSessionStarted || e.Evt == EvtError)
	})
	a.Equal(EvtSessionStarted, evt.Evt, "dial failed: %v", evt.Data)
	id, _ := evt.Data["session_id"].(string)
	a.NotEmpty(id)
	return id
}

// waitRelayPool returns the relay reconnect tokens d stores for session
// id once the two peers have exchanged them.
func waitRelayPool(t *testing.T, d *Daemon, id string) [][]byte {
	a := require.New(t)
	deadline := time.Now().Add(testEventTimeout)
	for {
		if pool := loadRelayPool(d.store(), id); len(pool) > 0 {
			return pool
		}
		a.True(time.Now().Before(deadline), "no relay pool for %s", id)
		time.Sleep(10 * time.Millisecond)
	}
}

// relayPair connects client to server through relay, on a relay token
// that server generated after it started, and returns the session ID and
// the token. Both sides hold the session's reconnect tokens.
func relayPair(
	t *testing.T,
	server *Daemon, serverRec *eventRecorder,
	client *Daemon, clientRec *eventRecorder,
	relay *fakeRelay,
) (string, string) {
	trustPeer(t, server, client)
	trustPeer(t, client, server)
	startRelayServer(t, server, serverRec, relay)
	token := generateRelayToken(t, server, serverRec, "token")
	id := dialRelay(t, client, clientRec, relay, token)
	waitRelayPool(t, server, id)
	waitRelayPool(t, client, id)
	return id, token
}

// A relay session on a token other than the startup token can resume
// after its connection drops, while the startup token still waits.
func TestRelaySessionOnGeneratedTokenResumes(t *testing.T) {
	a := require.New(t)
	relay := newFakeRelay(t)
	server, serverRec := newTestDaemon(t, VerificationModeQuick, false)
	client, clientRec := newTestDaemon(t, VerificationModeQuick, false)
	id, token := relayPair(t, server, serverRec, client, clientRec, relay)
	pool := waitRelayPool(t, server, id)
	registered := len(relay.created())

	relay.drop(token)

	created := relay.waitCreated(t, registered+1)
	a.Equal(hex.EncodeToString(pool[0]), created[registered])
	clientRec.waitFor(t, isEvent(EvtSessionReconnected))
}

// The startup relay token is announced with relay_token only while the
// token list holds it unused.
func TestAnnounceRelayToken(t *testing.T) {
	tests := []struct {
		name     string
		listed   bool
		consumed bool
		want     bool
	}{
		{name: "listed", listed: true, want: true},
		{name: "used", listed: true, consumed: true},
		{name: "expired or link lost"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			d, rec := newTestDaemon(t, VerificationModeQuick, false)
			first := relayToken{
				Token: "startup", Mode: "random",
				listener: &tokenTracker{},
			}
			if tt.listed {
				listed := first
				listed.Consumed = tt.consumed
				d.mu.Lock()
				d.relayTokens = []relayToken{listed}
				d.mu.Unlock()
			}

			d.announceRelayToken(first)

			rec.waitFor(t, isEvent(EvtRelayTokens))
			rec.mu.Lock()
			defer rec.mu.Unlock()
			announced := false
			for _, e := range rec.events {
				announced = announced || e.Evt == EvtRelayToken
			}
			a.Equal(tt.want, announced)
		})
	}
}

// A relay token whose listener loses its relay connection is reported
// and removed from the token list.
func TestRelayLinkLossIsReported(t *testing.T) {
	a := require.New(t)
	relay := newFakeRelay(t)
	server, rec := newTestDaemon(t, VerificationModeQuick, false)
	startup := startRelayServer(t, server, rec, relay)

	relay.drop(startup)

	evt := rec.waitFor(t, func(e recordedEvent) bool {
		return e.Evt == EvtError && e.Data["code"] == "relay_link_lost"
	})
	a.Contains(evt.Data["error"], startup)
	server.mu.RLock()
	defer server.mu.RUnlock()
	a.Empty(server.relayTokens)
}
