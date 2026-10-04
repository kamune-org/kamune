package main

import (
	"context"
	"fmt"
	"net"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/storage"
)

// chatWith starts a chat in mode with a peer that runs handler on its side
// of the session, and returns the model in that chat.
func chatWith(
	t *testing.T, mode inputMode, handler func(*kamune.Transport) error,
) *model {
	t.Helper()
	m := newTestModel()
	m.store = openTestStore(t)
	m.mode = mode
	m.state = stateConnecting
	m.att = newAttempt()
	m.Update(connectedMsg{att: m.att, transport: dialPipe(t, handler)})
	require.New(t).Equal(stateChat, m.state)
	return m
}

func TestChat_EscEndsSessionInEveryMode(t *testing.T) {
	keys := []struct {
		name string
		key  tea.KeyMsg
	}{
		{"esc", tea.KeyMsg{Type: tea.KeyEsc}},
		{"ctrl+c", tea.KeyMsg{Type: tea.KeyCtrlC}},
	}
	modes := []inputMode{
		modeDirectDial, modeDirectServe, modeRelayDial, modeRelayServe,
	}
	for _, mode := range modes {
		for _, k := range keys {
			t.Run(fmt.Sprint(mode, k.name), func(t *testing.T) {
				a := require.New(t)
				peerErr := make(chan error, 1)
				m := chatWith(t, mode, func(t *kamune.Transport) error {
					_, _, err := t.ReceivePayload()
					peerErr <- err
					return nil
				})
				sess := m.sess

				updated := make(chan struct{})
				go func() {
					defer close(updated)
					m.Update(k.key)
				}()
				waitFor(t, updated)
				a.Nil(m.sess)
				a.ErrorIs(waitFor(t, peerErr), kamune.ErrPeerDisconnected)
				_, open := <-sess.stop
				a.False(open, "the session goroutines were not stopped")
			})
		}
	}
}

// peerSession returns the dialer's side of a session with a server that
// runs handler on its side, and a channel that gets what handler's
// ReceivePayload returns.
func peerSession(t *testing.T) (*kamune.Transport, <-chan error) {
	t.Helper()
	peerErr := make(chan error, 1)
	tr := dialPipe(t, func(t *kamune.Transport) error {
		_, _, err := t.ReceivePayload()
		peerErr <- err
		return nil
	})
	return tr, peerErr
}

func TestConnected_UnwantedSessionIsClosed(t *testing.T) {
	tests := []struct {
		name  string
		state appState
		// current is whether the session comes from the attempt in
		// progress.
		current bool
	}{
		{"during a chat", stateChat, false},
		{"from a cancelled attempt", stateConnecting, false},
		{"on the welcome screen", stateWelcome, true},
		{"on the history screen", stateHistory, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			m := chatWith(t, modeDirectServe, func(*kamune.Transport) error {
				return nil
			})
			sess := m.sess
			m.state = tt.state
			att := newAttempt()
			if tt.current {
				m.att = att
			} else {
				m.att = newAttempt()
			}

			tr, peerErr := peerSession(t)
			release := make(chan struct{})
			m.Update(connectedMsg{att: att, transport: tr, release: release})
			a.Equal(tt.state, m.state)
			a.Same(sess, m.sess)
			a.ErrorIs(waitFor(t, peerErr), kamune.ErrPeerDisconnected)
			_, open := <-release
			a.False(open)
		})
	}
}

func TestConnected_DuringPromptEndsPrompt(t *testing.T) {
	a := require.New(t)
	m := newTestModel()
	m.store = openTestStore(t)
	m.mode = modeDirectServe
	m.state = stateVerify
	m.att = newAttempt()
	respCh := make(chan error, 1)
	m.verifyReq = &verifyRequest{peer: &storage.Peer{}, responseCh: respCh}

	tr, _ := peerSession(t)
	m.Update(connectedMsg{att: m.att, transport: tr})
	a.Equal(stateChat, m.state)
	a.Same(tr, m.sess.t)
	a.Nil(m.verifyReq)
	a.ErrorIs(waitFor(t, respCh), errPromptNotShown)
}

func TestServe_HandlerKeepsSessionUntilReleased(t *testing.T) {
	a := require.New(t)
	accept := func(*storage.Storage, *storage.Peer) error { return nil }
	clientNet, serverNet := net.Pipe()
	delivered := make(chan connectedMsg, 1)
	srv, err := serve("", openTestStore(t), accept,
		func(t *kamune.Transport, release chan struct{}) {
			delivered <- connectedMsg{transport: t, release: release}
		},
		kamune.ServeWithListener(newPipeListener(serverNet)),
	)
	a.NoError(err)
	dialer, err := kamune.NewDialer(
		"", openTestStore(t), accept,
		kamune.DialWithFunc(func(string) (kamune.Conn, error) {
			return kamune.NewConn(clientNet), nil
		}),
	)
	a.NoError(err)
	client, err := dialer.Dial()
	a.NoError(err)
	t.Cleanup(func() { _ = client.CloseAbort() })

	msg := waitFor(t, delivered)
	// The handler has not returned, so the session still works.
	received := make(chan error, 1)
	go func() {
		_, _, err := msg.transport.ReceivePayload()
		received <- err
	}()
	_, err = client.Send(
		kamune.Bytes([]byte("hi")), kamune.RouteExchangeMessages,
	)
	a.NoError(err)
	a.NoError(waitFor(t, received))

	go func() {
		_, _, err := client.ReceivePayload()
		received <- err
	}()
	closeSession(msg.transport, msg.release)
	a.ErrorIs(waitFor(t, received), kamune.ErrPeerDisconnected)
	a.NoError(srv.Shutdown(context.Background()))
}
