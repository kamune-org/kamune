package main

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/pkg/fingerprint"
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

// stopReconnect keeps d's dialed session id from reconnecting, so that
// the server's resume listeners wait for nobody.
func stopReconnect(t *testing.T, d *Daemon, id string) {
	waitForSession(t, d, id).stop()
}

// hexTokens returns tokens in hex.
func hexTokens(tokens [][]byte) []string {
	out := make([]string, len(tokens))
	for i, token := range tokens {
		out[i] = hex.EncodeToString(token)
	}
	return out
}

// A resume listener uses each reconnect token once: when it ends before
// the peer comes back, the next one has another token, and the tokens
// used are no longer stored.
func TestRelayResumeTokensAreSingleUse(t *testing.T) {
	a := require.New(t)
	relay := newFakeRelay(t)
	server, serverRec := newTestDaemon(t, VerificationModeQuick, false)
	client, clientRec := newTestDaemon(t, VerificationModeQuick, false)
	id, token := relayPair(t, server, serverRec, client, clientRec, relay)
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

	deadline := time.Now().Add(testEventTimeout)
	for len(loadRelayPool(server.store(), id)) != len(pool)-2 {
		a.True(time.Now().Before(deadline), "used tokens still stored")
		time.Sleep(10 * time.Millisecond)
	}
	left := hexTokens(loadRelayPool(server.store(), id))
	a.NotContains(left, first)
	a.NotContains(left, second)
}

// Once the resume window has passed, a resume listener that ends is not
// registered again.
func TestRelayResumeStopsAfterWindow(t *testing.T) {
	a := require.New(t)
	relay := newFakeRelay(t)
	server, serverRec := newTestDaemon(t, VerificationModeQuick, false)
	client, clientRec := newTestDaemon(t, VerificationModeQuick, false)
	server.relayResumeWindow = 0
	id, token := relayPair(t, server, serverRec, client, clientRec, relay)
	stopReconnect(t, client, id)
	registered := len(relay.created())

	relay.drop(token)
	first := relay.waitCreated(t, registered+1)[registered]
	relay.drop(first)

	serverRec.waitFor(t, func(e recordedEvent) bool {
		msg, _ := e.Data["message"].(string)
		return e.Evt == EvtLogEntry &&
			strings.Contains(msg, "was not resumed through the relay")
	})
	a.Len(relay.created(), registered+1)
}

// waitRelayTokenListed waits until d lists the relay token token.
func waitRelayTokenListed(t *testing.T, d *Daemon, token string) {
	a := require.New(t)
	deadline := time.Now().Add(testEventTimeout)
	for !relayTokenListed(d, token) {
		a.True(time.Now().Before(deadline), "token %s not listed", token)
		time.Sleep(10 * time.Millisecond)
	}
}

// relayTokenListed reports whether d lists the relay token token.
func relayTokenListed(d *Daemon, token string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, rt := range d.relayTokens {
		if rt.Token == token {
			return true
		}
	}
	return false
}

// A resume listener whose token the user removes, or whose session the
// user deletes, is not registered again, and the session's reconnect
// tokens are dropped.
func TestRemovedRelayResumeListenerIsNotRenewed(t *testing.T) {
	tests := []struct {
		name   string
		remove func(d *Daemon, id, token string)
	}{
		{
			name: "remove_relay_token",
			remove: func(d *Daemon, _, token string) {
				d.handleRemoveRelayToken(Command{
					ID: "remove", Params: mustJSON(MapS{"token": token}),
				})
			},
		},
		{
			name: "delete_history_session",
			remove: func(d *Daemon, id, _ string) {
				d.handleDeleteHistorySession(Command{
					ID: "remove", Params: mustJSON(MapS{"session_id": id}),
				})
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			relay := newFakeRelay(t)
			server, serverRec := newTestDaemon(
				t, VerificationModeQuick, false,
			)
			client, clientRec := newTestDaemon(
				t, VerificationModeQuick, false,
			)
			id, token := relayPair(
				t, server, serverRec, client, clientRec, relay,
			)
			stopReconnect(t, client, id)
			registered := len(relay.created())

			relay.drop(token)
			resume := relay.waitCreated(t, registered+1)[registered]
			waitRelayTokenListed(t, server, resume)
			tt.remove(server, id, resume)
			evt := serverRec.waitFor(t, func(e recordedEvent) bool {
				return e.ID == "remove"
			})
			a.Equal(EvtResponse, evt.Evt, "remove failed: %v", evt.Data)

			// The resume ends at once, without another registration.
			serverRec.waitFor(t, func(e recordedEvent) bool {
				msg, _ := e.Data["message"].(string)
				return e.Evt == EvtLogEntry &&
					strings.Contains(msg, "was removed")
			})
			a.Len(relay.created(), registered+1)
			a.Empty(loadRelayPool(server.store(), id))
			a.False(relayTokenListed(server, resume))
		})
	}
}

// A reconnect token whose registration fails once the relay has it is
// not offered to the relay again.
func TestRelayResumeDropsTokensTheRelayHad(t *testing.T) {
	for _, mode := range []string{"wrong token", "hang up"} {
		t.Run(mode, func(t *testing.T) {
			a := require.New(t)
			relay := newFakeRelay(t)
			server, serverRec := newTestDaemon(
				t, VerificationModeQuick, false,
			)
			client, clientRec := newTestDaemon(
				t, VerificationModeQuick, false,
			)
			id, token := relayPair(
				t, server, serverRec, client, clientRec, relay,
			)
			pool := hexTokens(waitRelayPool(t, server, id))
			stopReconnect(t, client, id)
			if mode == "wrong token" {
				relay.wrongToken.Store(true)
			} else {
				relay.hangUp.Store(true)
			}

			relay.drop(token)
			serverRec.waitFor(t, func(e recordedEvent) bool {
				msg, _ := e.Data["message"].(string)
				return e.Evt == EvtLogEntry &&
					strings.Contains(msg, "No relay reconnect tokens left")
			})
			asked := relay.askedFor()
			a.Len(asked, len(pool))
			for _, token := range pool {
				a.Contains(asked, token)
			}
		})
	}
}

// relayTokenSent tells a registration that failed before the relay had
// its token from one that failed after.
func TestRelayTokenSent(t *testing.T) {
	relay := newFakeRelay(t)
	gone := newFakeRelay(t)
	gone.close()

	tests := []struct {
		name       string
		addr       string
		password   string
		wrongToken bool
		hangUp     bool
		want       bool
	}{
		{name: "relay unreachable", addr: gone.addr()},
		{name: "password refused", addr: relay.addr(), password: "pw"},
		{name: "wrong token", addr: relay.addr(), wrongToken: true, want: true},
		{name: "hang up", addr: relay.addr(), hangUp: true, want: true},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			relay.wrongToken.Store(tt.wrongToken)
			relay.hangUp.Store(tt.hangUp)
			token := []byte(strings.Repeat(string(rune('a'+i)), 32))

			_, _, _, _, err := listenRelay(
				t.Context(), testEventTimeout, tt.addr, tt.password,
				false, token,
			)
			a.Error(err)
			a.Equal(tt.want, relayTokenSent(err), err.Error())
		})
	}
}

// A relay session that either side closes leaves no reconnect tokens,
// and the server registers no resume listener for it.
func TestClosedRelaySessionDropsReconnectTokens(t *testing.T) {
	for _, closer := range []string{"client", "server"} {
		t.Run(closer, func(t *testing.T) {
			a := require.New(t)
			relay := newFakeRelay(t)
			server, serverRec := newTestDaemon(
				t, VerificationModeQuick, false,
			)
			client, clientRec := newTestDaemon(
				t, VerificationModeQuick, false,
			)
			id, _ := relayPair(
				t, server, serverRec, client, clientRec, relay,
			)
			registered := len(relay.created())

			d, rec, other := client, clientRec, serverRec
			if closer == "server" {
				d, rec, other = server, serverRec, clientRec
			}
			waitForSession(t, d, id)
			d.handleCloseSession(Command{
				ID: "close", Params: mustJSON(MapS{"session_id": id}),
			})
			evt := rec.waitFor(t, func(e recordedEvent) bool {
				return e.ID == "close"
			})
			a.Equal(EvtResponse, evt.Evt, "close failed: %v", evt.Data)
			other.waitFor(t, isEvent(EvtSessionClosed))

			deadline := time.Now().Add(testEventTimeout)
			for _, d := range []*Daemon{server, client} {
				for len(loadRelayPool(d.store(), id)) > 0 {
					a.True(time.Now().Before(deadline), "tokens kept")
					time.Sleep(10 * time.Millisecond)
				}
			}
			a.Len(relay.created(), registered)
		})
	}
}

// get_share_info hands out the relay token of the last card again while
// no peer has used it and it has more than half its lifetime left, and
// registers a new one otherwise.
func TestShareInfoReusesFreshRelayToken(t *testing.T) {
	a := require.New(t)
	relay := newFakeRelay(t)
	d, rec := newTestDaemon(t, VerificationModeQuick, false)
	startRelayServer(t, d, rec, relay)
	share := func(id ID) string {
		d.handleGetShareInfo(Command{ID: id})
		evt := rec.waitFor(t, func(e recordedEvent) bool { return e.ID == id })
		a.Equal(EvtResponse, evt.Evt, "share failed: %v", evt.Data)
		info, _ := evt.Data["relay_info"].(map[string]any)
		token, _ := info["token"].(string)
		a.NotEmpty(token)
		return token
	}

	first := share("share-1")
	a.Equal(first, share("share-2"))
	a.Len(relay.created(), 2)

	// Past half its lifetime, the token is not handed out again.
	d.mu.Lock()
	for i, rt := range d.relayTokens {
		if rt.Token == first {
			d.relayTokens[i].ExpiresAt = time.Now().Add(rt.TTL / 4)
		}
	}
	d.mu.Unlock()
	second := share("share-3")
	a.NotEqual(first, second)
	a.Len(relay.created(), 3)

	// Nor is a token that the user removed.
	d.handleRemoveRelayToken(Command{
		ID: "remove", Params: mustJSON(MapS{"token": second}),
	})
	evt := rec.waitFor(t, func(e recordedEvent) bool { return e.ID == "remove" })
	a.Equal(EvtResponse, evt.Evt, "remove failed: %v", evt.Data)
	third := share("share-4")
	a.NotEqual(second, third)
	a.Len(relay.created(), 4)
}

// An expired relay token leaves the token list and its listener leaves
// the server's listeners.
func TestExpiredRelayTokenIsRemoved(t *testing.T) {
	a := require.New(t)
	relay := newFakeRelay(t)
	relay.ttl.Store(1)
	server, rec := newTestDaemon(t, VerificationModeQuick, false)
	startRelayServer(t, server, rec, relay)

	rec.waitFor(t, func(e recordedEvent) bool {
		tokens, ok := e.Data["tokens"].([]any)
		return e.Evt == EvtRelayTokens && ok && len(tokens) == 0
	})
	// The server keeps running, and says that no peer can connect.
	rec.waitFor(t, func(e recordedEvent) bool {
		msg, _ := e.Data["message"].(string)
		return e.Evt == EvtLogEntry &&
			strings.Contains(msg, "no relay token left")
	})
	server.mu.RLock()
	a.Empty(server.relayTokens)
	a.NotNil(server.server)
	ml := server.relayListeners
	server.mu.RUnlock()
	deadline := time.Now().Add(testEventTimeout)
	for {
		ml.mu.Lock()
		n := len(ml.listeners)
		ml.mu.Unlock()
		if n == 0 {
			break
		}
		a.True(time.Now().Before(deadline), "expired listener kept")
		time.Sleep(10 * time.Millisecond)
	}
}

func TestGenerateRelayTokenParams(t *testing.T) {
	a := require.New(t)
	relay := newFakeRelay(t)
	d, rec := newTestDaemon(t, VerificationModeQuick, false)
	startRelayServer(t, d, rec, relay)
	peer := newTestPeerKey(t)
	static := hex.EncodeToString(p2pTokenFor(t, d, peer))

	tests := []struct {
		name   string
		params string
		code   string
		mode   string
		token  string
	}{
		{name: "no params", mode: "random"},
		{name: "empty", params: `{}`, mode: "random"},
		{
			name:   "peer key",
			params: `{"peer_pub_b64":"` + fingerprint.Base64(peer) + `"}`,
			mode:   "static",
			token:  static,
		},
		{name: "not json", params: `{"peer_pub_b64":`, code: "invalid_params"},
		{name: "wrong type", params: `{"peer_pub_b64":5}`, code: "invalid_params"},
		{
			name:   "bad base64",
			params: `{"peer_pub_b64":"not a key!"}`,
			code:   "invalid_peer_key",
		},
		{
			name:   "short key",
			params: `{"peer_pub_b64":"AAAA"}`,
			code:   "invalid_peer_key",
		},
	}
	for i, tt := range tests {
		id := ID(fmt.Sprintf("gen-%d", i))
		cmd := Command{ID: id}
		if tt.params != "" {
			cmd.Params = []byte(tt.params)
		}
		d.handleGenerateRelayToken(cmd)
		evt := rec.waitFor(t, func(e recordedEvent) bool { return e.ID == id })
		if tt.code != "" {
			a.Equal(EvtError, evt.Evt, tt.name)
			a.Equal(tt.code, evt.Data["code"], tt.name)
			continue
		}
		a.Equal(EvtResponse, evt.Evt, "%s: %v", tt.name, evt.Data)
		a.Equal(tt.mode, evt.Data["mode"], tt.name)
		if tt.token != "" {
			a.Equal(tt.token, evt.Data["token"], tt.name)
		}
	}
}
