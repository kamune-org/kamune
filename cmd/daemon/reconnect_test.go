package main

import (
	"context"
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

func TestIncognitoDialSessionReconnects(t *testing.T) {
	a := require.New(t)
	server, serverRec := newTestDaemon(t, VerificationModeQuick, false)
	client, clientRec := newTestDaemon(t, VerificationModeQuick, true)
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
