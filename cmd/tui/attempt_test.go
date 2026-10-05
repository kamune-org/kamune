package main

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/storage"
)

// idleServer returns a server whose listener takes no connections, and the
// listener, which is closed when the server is.
func idleServer(t *testing.T, store *storage.Storage) (
	*kamune.Server, *pipeListener,
) {
	t.Helper()
	l := &pipeListener{
		conns:  make(chan kamune.Conn),
		closed: make(chan struct{}),
	}
	// The listener takes no connections, so the verifier never runs; the
	// core still requires one.
	reject := func(*storage.Storage, *storage.Peer) error {
		return errors.New("idle server takes no peers")
	}
	srv, err := kamune.NewServer(
		"", func(*kamune.Transport) error { return nil }, store, reject,
		kamune.ServeWithListener(l),
	)
	require.New(t).NoError(err)
	return srv, l
}

func TestUpdate_DropsMessagesOfEndedAttempts(t *testing.T) {
	tests := []struct {
		name string
		msg  func(*testing.T, *attempt, *storage.Storage) (any, func(*testing.T))
	}{
		{"connect failed", func(_ *testing.T, old *attempt, _ *storage.Storage) (
			any, func(*testing.T),
		) {
			return connectFailedMsg{old, errors.New("old dial")}, nil
		}},
		{"verify request", func(_ *testing.T, old *attempt, _ *storage.Storage) (
			any, func(*testing.T),
		) {
			respCh := make(chan error, 1)
			msg := verifyRequest{
				att:        old,
				peer:       &storage.Peer{},
				responseCh: respCh,
			}
			return msg, func(t *testing.T) {
				require.New(t).ErrorIs(
					waitFor(t, respCh), errAttemptCancelled,
				)
			}
		}},
		{"relay ready", func(t *testing.T, old *attempt, store *storage.Storage) (
			any, func(*testing.T),
		) {
			srv, l := idleServer(t, store)
			msg := relayReadyMsg{att: old, srv: srv, token: []byte("old")}
			return msg, func(t *testing.T) {
				// The server of the cancelled attempt is closed.
				waitFor(t, l.closed)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			m := newTestModel()
			m.store = openTestStore(t)
			m.mode = modeDirectServe
			m.inputs = []textinput.Model{mkInput("addr", ":9000")}
			old := newAttempt()
			m.att = old
			m.cancelConnect()

			// The user has started a server since.
			srv, l := idleServer(t, m.store)
			m.att = newAttempt()
			m.srv = srv
			m.state = stateConnecting

			msg, check := tt.msg(t, old, m.store)
			m.Update(msg)
			a.Equal(stateConnecting, m.state)
			a.Nil(m.connectErr)
			a.Nil(m.relayToken)
			a.Same(srv, m.srv)
			select {
			case <-l.closed:
				a.Fail("the server of the new attempt was closed")
			default:
			}
			if check != nil {
				check(t)
			}
		})
	}
}

func TestDial_CancelEndsHandshake(t *testing.T) {
	a := require.New(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	a.NoError(err)
	t.Cleanup(func() { _ = ln.Close() })
	// The server takes the connection and never answers.
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := dial(ctx, ln.Addr().String(), openTestStore(t),
			func(*storage.Storage, *storage.Peer) error { return nil },
		)
		done <- err
	}()
	c := waitFor(t, accepted)
	t.Cleanup(func() { _ = c.Close() })

	cancel()
	a.ErrorIs(waitFor(t, done), context.Canceled)
}

func TestServe_BindErrorEndsAttempt(t *testing.T) {
	a := require.New(t)
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	a.NoError(err)
	t.Cleanup(func() { _ = taken.Close() })

	m := newTestModel()
	m.store = openTestStore(t)
	m.state = stateWelcome
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'2'}})
	a.Equal(modeDirectServe, m.mode)
	m.inputs[0].SetValue(taken.Addr().String())

	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	a.Equal(stateConnecting, m.state)
	a.NotNil(cmd, "the bind error is not reported")
	m.Update(cmd())
	a.Equal(stateWelcome, m.state)
	a.Nil(m.att)
	a.Nil(m.srv)
	a.ErrorContains(m.connectErr, "listening tcp")
	a.Contains(m.viewWelcome(), "listening tcp")
}

func TestServe_StopEndsAttempt(t *testing.T) {
	tests := []struct {
		name    string
		mode    inputMode
		wantErr error
	}{
		{"direct server", modeDirectServe, errServerStopped},
		{"relay server", modeRelayServe, errRelaySessionEnded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			m := newTestModel()
			m.store = openTestStore(t)
			m.mode = tt.mode
			m.inputs = []textinput.Model{mkInput("addr", "")}
			msgs := make(chan tea.Msg, 1)
			m.send = func(msg tea.Msg) { msgs <- msg }
			m.att = newAttempt()
			m.state = stateConnecting
			l := &pipeListener{
				conns:  make(chan kamune.Conn),
				closed: make(chan struct{}),
			}
			srv, err := serve("", m.store, m.mkVerifier(m.att),
				func(*kamune.Transport, chan struct{}) {},
				serverStopped(m.att, m.mode, m.send),
				kamune.ServeWithListener(l),
			)
			a.NoError(err)
			m.srv = srv

			// The listener ends while the server waits for a peer, as a
			// relay listener does once its connection is over.
			_ = l.Close()
			m.Update(waitFor(t, msgs))
			a.Equal(stateWelcome, m.state)
			a.Nil(m.att)
			a.Nil(m.srv)
			a.ErrorIs(m.connectErr, tt.wantErr)
		})
	}
}
