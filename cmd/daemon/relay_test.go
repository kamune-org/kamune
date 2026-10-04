package main

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestStampRelaySession_TwoConsumedTokens(t *testing.T) {
	a := require.New(t)
	first := &tokenTracker{}
	second := &tokenTracker{}
	tokens := []relayToken{
		{Consumed: true, listener: first},
		{Consumed: true, listener: second},
	}
	stampRelaySession(tokens, second, "session-b")
	a.Empty(first.sessionID)
	a.Equal("session-b", second.sessionID)
	a.Empty(tokens[0].sessionID)
	a.Equal("session-b", tokens[1].sessionID)
}

func TestStampRelaySession_AfterSliceRemoval(t *testing.T) {
	a := require.New(t)
	tt := &tokenTracker{}
	stampRelaySession(nil, tt, "session-a")
	a.Equal("session-a", tt.sessionID)
}

func TestRelayReconnectLoop_EmptySessionDoesNotQueryRoot(t *testing.T) {
	a := require.New(t)
	id := relaySessionID(&tokenTracker{}, nil)
	a.Empty(id)
	_, ok := loadRelayPool(nil, id)
	a.False(ok)
}

// stallingRelay accepts TCP connections and never answers on them, as a
// relay that has stopped responding would. Close closes the connections
// it holds, which ends a relay handshake waiting on them.
type stallingRelay struct {
	ln     net.Listener
	mu     sync.Mutex
	conns  []net.Conn
	closed bool
}

func newStallingRelay(t *testing.T) *stallingRelay {
	a := require.New(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	a.NoError(err)
	r := &stallingRelay{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			r.mu.Lock()
			if r.closed {
				_ = conn.Close()
			} else {
				r.conns = append(r.conns, conn)
			}
			r.mu.Unlock()
		}
	}()
	t.Cleanup(r.Close)
	return r
}

func (r *stallingRelay) addr() string { return "tcp://" + r.ln.Addr().String() }

func (r *stallingRelay) Close() {
	_ = r.ln.Close()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	for _, conn := range r.conns {
		_ = conn.Close()
	}
	r.conns = nil
}

// useStallingRelay makes d's running server a relay server on a relay
// that never answers.
func useStallingRelay(t *testing.T, d *Daemon) *stallingRelay {
	relay := newStallingRelay(t)
	d.mu.Lock()
	d.serverTransport = "relay"
	d.relayListeners = newMultiListener()
	d.relayAddr = relay.addr()
	d.mu.Unlock()
	return relay
}

func TestRelayTokenCommandsDoNotBlockCommandLoop(t *testing.T) {
	tests := []struct {
		cmd  CMD
		code string
	}{
		{cmd: CmdGenerateRelayToken, code: "relay_listen_failed"},
		{cmd: CmdGetShareInfo, code: "relay_token_failed"},
	}
	for _, tt := range tests {
		t.Run(string(tt.cmd), func(t *testing.T) {
			a := require.New(t)
			d, rec := newTestDaemon(t, VerificationModeQuick, false)
			startTestServer(t, d, rec)
			relay := useStallingRelay(t, d)

			d.handleCommand(Command{
				Type: "cmd", CMD: tt.cmd, ID: "token",
				Params: []byte("{}"),
			})
			d.handleCommand(Command{
				Type: "cmd", CMD: CmdGetStatus, ID: "status",
			})

			// The relay has not answered, and the next command did
			// not wait for it.
			rec.waitFor(t, func(e recordedEvent) bool {
				return e.ID == "status"
			})
			rec.mu.Lock()
			var ids []ID
			for _, e := range rec.events {
				ids = append(ids, e.ID)
			}
			rec.mu.Unlock()
			a.NotContains(ids, ID("token"), "answered before the relay")

			relay.Close()
			evt := rec.waitFor(t, func(e recordedEvent) bool {
				return e.ID == "token"
			})
			a.Equal(EvtError, evt.Evt)
			a.Equal(tt.code, evt.Data["code"])
		})
	}
}

func TestRelayRegistrationTimesOut(t *testing.T) {
	a := require.New(t)
	d, rec := newTestDaemon(t, VerificationModeQuick, false)
	d.relayTimeout = 200 * time.Millisecond
	startTestServer(t, d, rec)
	useStallingRelay(t, d)

	d.handleGenerateRelayToken(Command{ID: "token"})

	evt := rec.waitFor(t, func(e recordedEvent) bool {
		return e.ID == "token"
	})
	a.Equal(EvtError, evt.Evt)
	a.Equal("relay_listen_failed", evt.Data["code"])
	a.Contains(evt.Data["error"], "deadline exceeded")
}
