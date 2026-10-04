package main

import (
	"bytes"
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestStampRelaySession(t *testing.T) {
	a := require.New(t)
	first := &tokenTracker{}
	second := &tokenTracker{}
	stampRelaySession(second, "session-b")
	stampRelaySession(nil, "session-c")
	a.Empty(first.sessionID)
	a.Equal("session-b", second.sessionID)
}

func TestLoadRelayPoolWithoutSession(t *testing.T) {
	a := require.New(t)
	a.Empty(loadRelayPool(nil, ""))
}

// stallingRelay accepts TCP connections and never answers on them, as a
// relay that has stopped responding would. Close closes the connections
// it holds, which ends a relay handshake waiting on them.
type stallingRelay struct {
	ln       net.Listener
	mu       sync.Mutex
	conns    []net.Conn
	accepted int
	closed   bool
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
			r.accepted++
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

// acceptedConns returns how many connections the relay has accepted.
func (r *stallingRelay) acceptedConns() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.accepted
}

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

func TestRelayDialTimesOut(t *testing.T) {
	a := require.New(t)
	d, rec := newTestDaemon(t, VerificationModeQuick, false)
	d.relayTimeout = 200 * time.Millisecond
	relay := newStallingRelay(t)

	d.handleDial(Command{
		ID: "dial",
		Params: mustJSON(DialParams{
			Transport: "relay",
			RelayAddr: relay.addr(),
			Token:     strings.Repeat("ab", 16),
		}),
	})

	evt := rec.waitFor(t, func(e recordedEvent) bool {
		return e.ID == "dial"
	})
	a.Equal(EvtError, evt.Evt)
	a.Equal("dial_failed", evt.Data["code"])
	a.Contains(evt.Data["error"], "deadline exceeded")

	// The failed dial no longer holds the storage.
	deadline := time.Now().Add(testEventTimeout)
	for d.storageBusy() {
		a.True(time.Now().Before(deadline), "dial never ended")
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRelayMultiTokenDialHasOneTimeLimit(t *testing.T) {
	a := require.New(t)
	relay := newStallingRelay(t)
	tokens := make([][]byte, 5)
	for i := range tokens {
		tokens[i] = bytes.Repeat([]byte{byte(i + 1)}, 16)
	}

	dial, err := dialRelayFuncMultiToken(
		t.Context(), 200*time.Millisecond, relay.addr(), "", false, tokens,
	)
	a.NoError(err)
	_, err = dial("")
	a.ErrorIs(err, context.DeadlineExceeded)

	// The first token used up the limit, so no other token was tried.
	deadline := time.Now().Add(testEventTimeout)
	for relay.acceptedConns() == 0 {
		a.True(time.Now().Before(deadline), "relay accepted nothing")
		time.Sleep(10 * time.Millisecond)
	}
	a.Equal(1, relay.acceptedConns())
}
