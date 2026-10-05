package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/storage"
	"github.com/stretchr/testify/require"
)

// testEventTimeout bounds how long a test waits for an event. It only limits
// how long a broken test takes to fail.
const testEventTimeout = 30 * time.Second

type recordedEvent struct {
	Data map[string]any `json:"data"`
	Evt  Evt            `json:"evt"`
	ID   ID             `json:"id"`
}

// eventRecorder collects the events a daemon emits.
type eventRecorder struct {
	changed chan struct{}
	events  []recordedEvent
	mu      sync.Mutex
}

func newEventRecorder() *eventRecorder {
	return &eventRecorder{changed: make(chan struct{}, 1)}
}

func (r *eventRecorder) Write(p []byte) (int, error) {
	var e recordedEvent
	if err := json.Unmarshal(p, &e); err != nil {
		return 0, err
	}
	r.mu.Lock()
	r.events = append(r.events, e)
	r.mu.Unlock()
	select {
	case r.changed <- struct{}{}:
	default:
	}
	return len(p), nil
}

// waitFor returns the first recorded event that match accepts.
func (r *eventRecorder) waitFor(
	t *testing.T, match func(recordedEvent) bool,
) recordedEvent {
	t.Helper()
	deadline := time.After(testEventTimeout)
	for {
		r.mu.Lock()
		for _, e := range r.events {
			if match(e) {
				r.mu.Unlock()
				return e
			}
		}
		r.mu.Unlock()
		select {
		case <-r.changed:
		case <-deadline:
			t.Fatal("timed out waiting for an event")
		}
	}
}

func isEvent(evt Evt) func(recordedEvent) bool {
	return func(e recordedEvent) bool { return e.Evt == evt }
}

// newTestDaemon returns a daemon with an open unencrypted store, whose
// events are recorded. It is stopped when the test ends.
func newTestDaemon(
	t *testing.T, mode VerificationMode, incognito bool,
) (*Daemon, *eventRecorder) {
	a := require.New(t)
	d := NewDaemon()
	rec := newEventRecorder()
	d.output = json.NewEncoder(rec)
	a.NoError(d.openStorage(OpenStorageParams{
		StoragePath:    filepath.Join(t.TempDir(), "kamune.db"),
		DBNoPassphrase: true,
	}))
	d.verifMode = mode
	d.incognito = incognito
	t.Cleanup(func() {
		d.cancel()
		d.stopServer()
		d.wg.Wait()
		d.closeStore()
	})
	return d, rec
}

// trustPeer stores peer's identity in d as a known peer.
func trustPeer(t *testing.T, d, peer *Daemon) {
	a := require.New(t)
	pub, err := peer.store().PublicKey()
	a.NoError(err)
	a.NoError(d.store().StorePeer(&storage.Peer{
		Name:      "peer",
		PublicKey: pub,
		FirstSeen: time.Now(),
	}))
}

// startTestServer starts a TCP server on d and returns its address once it
// accepts connections.
func startTestServer(t *testing.T, d *Daemon, rec *eventRecorder) string {
	a := require.New(t)
	addr := fmt.Sprintf("127.0.0.1:%d", findFreePort(t))
	d.handleStartServer(Command{
		ID: "start", Params: mustJSON(StartServerParams{Addr: addr}),
	})
	rec.waitFor(t, isEvent(EvtServerStarted))

	deadline := time.Now().Add(testEventTimeout)
	for {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			a.NoError(conn.Close())
			return addr
		}
		a.True(time.Now().Before(deadline), "server never listened")
		time.Sleep(10 * time.Millisecond)
	}
}

// dialTestServer dials addr from d and returns the new session's ID.
func dialTestServer(
	t *testing.T, d *Daemon, rec *eventRecorder, addr string,
) string {
	a := require.New(t)
	d.handleDial(Command{
		ID: "dial", Params: mustJSON(DialParams{Addr: addr}),
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

// dropServerSession cuts the connection of the server's live session id
// without a close frame, as a network failure would.
func dropServerSession(t *testing.T, d *Daemon, id string) {
	a := require.New(t)
	var session *liveSession
	deadline := time.Now().Add(testEventTimeout)
	for session == nil {
		d.mu.RLock()
		session = d.sessions[id]
		d.mu.RUnlock()
		if session == nil {
			a.True(time.Now().Before(deadline), "no server session")
			time.Sleep(10 * time.Millisecond)
		}
	}
	a.NoError(session.snapshotTransport().CloseAbort())
}

// waitForSession returns d's live session id once it is registered.
func waitForSession(t *testing.T, d *Daemon, id string) *liveSession {
	a := require.New(t)
	deadline := time.Now().Add(testEventTimeout)
	for {
		d.mu.RLock()
		session := d.sessions[id]
		d.mu.RUnlock()
		if session != nil {
			return session
		}
		a.True(time.Now().Before(deadline), "no session %s", id)
		time.Sleep(10 * time.Millisecond)
	}
}

func TestDialSessionReconnects(t *testing.T) {
	a := require.New(t)
	server, serverRec := newTestDaemon(t, VerificationModeQuick, false)
	client, clientRec := newTestDaemon(t, VerificationModeQuick, false)
	trustPeer(t, server, client)
	trustPeer(t, client, server)

	addr := startTestServer(t, server, serverRec)
	id := dialTestServer(t, client, clientRec, addr)
	dropServerSession(t, server, id)

	evt := clientRec.waitFor(t, func(e recordedEvent) bool {
		return e.Evt == EvtSessionReconnected || e.Evt == EvtError ||
			e.Evt == EvtSessionClosed
	})
	a.Equal(EvtSessionReconnected, evt.Evt, "got %v", evt.Data)
	a.Equal(id, evt.Data["session_id"])
}

func TestIncognitoDialSessionEndsOnDrop(t *testing.T) {
	a := require.New(t)
	server, serverRec := newTestDaemon(t, VerificationModeQuick, false)
	client, clientRec := newTestDaemon(t, VerificationModeQuick, true)
	trustPeer(t, server, client)
	trustPeer(t, client, server)

	addr := startTestServer(t, server, serverRec)
	id := dialTestServer(t, client, clientRec, addr)
	dropServerSession(t, server, id)

	evt := clientRec.waitFor(t, func(e recordedEvent) bool {
		return e.Evt == EvtSessionReconnecting ||
			e.Evt == EvtSessionClosed
	})
	a.Equal(EvtSessionClosed, evt.Evt, "got %v", evt.Data)
	a.Equal(id, evt.Data["session_id"])
	// The dial goroutine leaves soon after the session closes.
	a.Eventually(func() bool { return !client.storageBusy() },
		testEventTimeout, 10*time.Millisecond)
}

func TestIncognitoSessionsLeaveNoRecord(t *testing.T) {
	tests := []struct {
		name                               string
		serverIncognito                    bool
		clientIncognito                    bool
		wantServerRecord, wantClientRecord bool
	}{
		{
			name:             "incognito server",
			serverIncognito:  true,
			wantClientRecord: true,
		},
		{
			name:             "incognito client",
			clientIncognito:  true,
			wantServerRecord: true,
		},
		{
			name:            "both incognito",
			serverIncognito: true,
			clientIncognito: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			server, serverRec := newTestDaemon(
				t, VerificationModeQuick, tt.serverIncognito,
			)
			client, clientRec := newTestDaemon(
				t, VerificationModeQuick, tt.clientIncognito,
			)
			trustPeer(t, server, client)
			trustPeer(t, client, server)

			addr := startTestServer(t, server, serverRec)
			id := dialTestServer(t, client, clientRec, addr)
			waitForSession(t, server, id)

			client.handleCloseSession(Command{
				ID:     "close",
				Params: mustJSON(CloseSessionParams{SessionID: id}),
			})
			serverRec.waitFor(t, func(e recordedEvent) bool {
				return e.Evt == EvtSessionClosed &&
					e.Data["session_id"] == id
			})

			for _, side := range []struct {
				d    *Daemon
				want bool
			}{
				{server, tt.wantServerRecord},
				{client, tt.wantClientRecord},
			} {
				ids, err := side.d.store().ListSessions()
				a.NoError(err)
				if side.want {
					a.Contains(ids, id)
				} else {
					a.Empty(ids)
				}
			}
		})
	}
}

func TestReconnectSessionStopsOnPermanentError(t *testing.T) {
	tests := []struct {
		fail      func() error
		name      string
		wantCalls int
	}{
		{
			name:      "missing storage",
			fail:      func() error { return kamune.ErrMissingStorage },
			wantCalls: 1,
		},
		{
			name: "resumption rejected",
			fail: func() error {
				return fmt.Errorf("handshake: %w", kamune.ErrResumptionRejected)
			},
			wantCalls: 1,
		},
		{
			name: "no resumption token",
			fail: func() error {
				return fmt.Errorf("handshake: %w", storage.ErrNotFound)
			},
			wantCalls: 1,
		},
		{
			name: "session not resumable",
			fail: func() error {
				return fmt.Errorf("%w: no peer", errNotResumable)
			},
			wantCalls: 1,
		},
		{
			name:      "panic",
			fail:      func() error { panic("reconnect bug") },
			wantCalls: 1,
		},
		{
			name: "network error",
			fail: func() error {
				return errors.New("dialing: connection refused")
			},
			wantCalls: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			d := newQuietDaemon()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			session := &liveSession{
				ID:           "session",
				reconnectCtx: ctx,
				reconnectFn: func(string) (*kamune.Transport, error) {
					calls++
					if calls > 1 {
						// Stop the retry loop at its next backoff.
						cancel()
					}
					return nil, tt.fail()
				},
			}

			a.False(d.reconnectSession(session))
			a.Equal(tt.wantCalls, calls)
		})
	}
}

// close_session leaves the closed session no resumption tokens, on both
// sides, and has nothing to clear for an incognito session, which is not
// stored.
func TestCloseSessionLeavesNoResumptionTokens(t *testing.T) {
	for _, incognito := range []bool{false, true} {
		t.Run(fmt.Sprintf("incognito=%v", incognito), func(t *testing.T) {
			a := require.New(t)
			server, serverRec := newTestDaemon(
				t, VerificationModeQuick, false,
			)
			client, clientRec := newTestDaemon(
				t, VerificationModeQuick, incognito,
			)
			trustPeer(t, server, client)
			trustPeer(t, client, server)
			addr := startTestServer(t, server, serverRec)
			id := dialTestServer(t, client, clientRec, addr)
			waitForSession(t, server, id)
			a.True(relayResumable(server.store(), id),
				"the server stored no resumption tokens")

			client.handleCloseSession(Command{
				ID:     "close",
				Params: mustJSON(CloseSessionParams{SessionID: id}),
			})
			evt := clientRec.waitFor(t, func(e recordedEvent) bool {
				return e.ID == "close"
			})
			a.Equal(EvtResponse, evt.Evt, "close_session: %v", evt.Data)
			serverRec.waitFor(t, func(e recordedEvent) bool {
				return e.Evt == EvtSessionClosed &&
					e.Data["session_id"] == id
			})

			for _, d := range []*Daemon{server, client} {
				a.False(relayResumable(d.store(), id))
			}
			ids, err := client.store().ListSessions()
			a.NoError(err)
			if incognito {
				a.Empty(ids, "close_session stored the session")
			}
			for _, msg := range logMessages(client) {
				a.NotContains(msg, "resumption tokens")
			}
		})
	}
}

// A session that started in incognito mode stays out of storage after
// set_incognito turns the mode off: on the side that dialed it in
// incognito mode, and on a server started in incognito mode. Messages
// sent and received after the switch are not stored either.
func TestIncognitoSessionStaysIncognito(t *testing.T) {
	tests := []struct {
		name            string
		serverIncognito bool
		clientIncognito bool
	}{
		{name: "incognito client", clientIncognito: true},
		{name: "incognito server", serverIncognito: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			server, serverRec := newTestDaemon(
				t, VerificationModeQuick, tt.serverIncognito,
			)
			client, clientRec := newTestDaemon(
				t, VerificationModeQuick, tt.clientIncognito,
			)
			trustPeer(t, server, client)
			trustPeer(t, client, server)
			addr := startTestServer(t, server, serverRec)
			id := dialTestServer(t, client, clientRec, addr)
			waitForSession(t, server, id)

			for _, d := range []*Daemon{server, client} {
				d.handleSetIncognito(Command{
					ID:     "off",
					Params: mustJSON(SetIncognitoParams{Enabled: false}),
				})
			}
			send := func(
				d *Daemon, rec, peerRec *eventRecorder, n int,
			) {
				t.Helper()
				cmdID := ID(fmt.Sprintf("send-%d", n))
				d.handleSendMessage(Command{
					ID: cmdID,
					Params: mustJSON(SendMessageParams{
						SessionID:  id,
						DataBase64: base64.StdEncoding.EncodeToString([]byte(cmdID)),
					}),
				})
				rec.waitFor(t, func(e recordedEvent) bool {
					return e.ID == cmdID && e.Evt == EvtMessageSent
				})
				peerRec.waitFor(t, func(e recordedEvent) bool {
					return e.Evt == EvtMessageReceived &&
						e.Data["data_base64"] ==
							base64.StdEncoding.EncodeToString([]byte(cmdID))
				})
			}
			send(client, clientRec, serverRec, 1)
			send(server, serverRec, clientRec, 2)

			incognitoSide := client
			if tt.serverIncognito {
				incognitoSide = server
			}
			ids, err := incognitoSide.store().ListSessions()
			a.NoError(err)
			a.Empty(ids, "an incognito session was stored")
		})
	}
}
