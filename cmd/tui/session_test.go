package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
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
	return chatSending(t, mode, handler, func(tea.Msg) {})
}

// chatSending is chatWith for a model whose goroutines report through
// send.
func chatSending(
	t *testing.T, mode inputMode, handler func(*kamune.Transport) error,
	send func(tea.Msg),
) *model {
	t.Helper()
	m := newTestModel()
	m.send = send
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
		func(error) {},
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

func TestSessionMsg_OnlyForTheChatOnScreen(t *testing.T) {
	type step struct {
		name string
		// next moves the model on from the chat that sends the message.
		next func(*testing.T, *model)
	}
	steps := []step{
		{"after esc", func(_ *testing.T, m *model) {
			m.Update(tea.KeyMsg{Type: tea.KeyEsc})
		}},
		{"in the next chat", func(t *testing.T, m *model) {
			m.Update(tea.KeyMsg{Type: tea.KeyEsc})
			m.state = stateConnecting
			m.att = newAttempt()
			tr, _ := peerSession(t)
			m.Update(connectedMsg{att: m.att, transport: tr})
			require.New(t).Equal(stateChat, m.state)
		}},
	}
	msgs := []tea.Msg{
		chatMessageMsg{sender: storage.SenderPeer, text: "late"},
		peerDisconnectedMsg{},
		receiveErrorMsg{err: errors.New("late")},
		historyLoadedMsg{messages: []chatLine{noticeLine(
			lipgloss.NewStyle(), "late",
		)}},
	}
	for _, st := range steps {
		for _, msg := range msgs {
			t.Run(fmt.Sprintf("%s %T", st.name, msg), func(t *testing.T) {
				a := require.New(t)
				m := chatWith(t, modeDirectServe, func(*kamune.Transport) error {
					return nil
				})
				old := m.sess
				st.next(t, m)
				before := len(m.messages)

				a.NotPanics(func() { m.Update(sessionMsg{old, msg}) })
				a.Len(m.messages, before)
				if m.sess != nil {
					history, err := m.store.GetChatHistory(m.sess.t.SessionID())
					a.NoError(err)
					a.Empty(history)
				}
			})
		}
	}
}

func TestChat_KeysDoNotWaitForTheNetwork(t *testing.T) {
	tests := []struct {
		name string
		key  tea.KeyMsg
		quit bool
	}{
		{"esc", tea.KeyMsg{Type: tea.KeyEsc}, false},
		{"ctrl+c", tea.KeyMsg{Type: tea.KeyCtrlC}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			// The peer never reads, so a write to it blocks.
			stuck := make(chan struct{})
			m := chatWith(t, modeDirectDial, func(*kamune.Transport) error {
				<-stuck
				return nil
			})
			t.Cleanup(func() { close(stuck) })

			update := func(msg tea.Msg) tea.Cmd {
				got := make(chan tea.Cmd, 1)
				go func() {
					_, cmd := m.Update(msg)
					got <- cmd
				}()
				return waitFor(t, got)
			}
			m.ta.SetValue("hello")
			update(tea.KeyMsg{Type: tea.KeyEnter})
			a.Empty(m.ta.Value())
			m.ta.SetValue("again")
			update(tea.KeyMsg{Type: tea.KeyEnter})
			a.Empty(m.ta.Value())

			cmd := update(tt.key)
			a.Nil(m.sess)
			if tt.quit {
				a.NotNil(cmd)
				a.IsType(tea.QuitMsg{}, cmd())
			}
		})
	}
}

func TestChat_MessagesAreSentInOrder(t *testing.T) {
	a := require.New(t)
	texts := []string{"one", "two", "three"}
	got := make(chan string, len(texts))
	msgs := make(chan tea.Msg, 16)
	m := chatSending(t, modeDirectDial, func(t *kamune.Transport) error {
		for range texts {
			b := kamune.Bytes(nil)
			if _, err := t.Receive(b); err != nil {
				return err
			}
			got <- string(b.GetValue())
		}
		return nil
	}, func(msg tea.Msg) { msgs <- msg })

	for _, text := range texts {
		m.ta.SetValue(text)
		m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	}
	for _, text := range texts {
		a.Equal(text, waitFor(t, got))
	}
	for range texts {
		var msg tea.Msg
		for {
			msg = waitFor(t, msgs)
			if sm, ok := msg.(sessionMsg); ok {
				if _, ok := sm.msg.(sentMsg); ok {
					break
				}
			}
		}
		m.Update(msg)
	}
	var shown []string
	for _, l := range m.messages {
		if l.message {
			a.Equal(storage.SenderLocal, l.sender)
			shown = append(shown, l.text)
		}
	}
	a.Equal(texts, shown)
	history, err := m.store.GetChatHistory(m.sess.t.SessionID())
	a.NoError(err)
	a.Len(history, len(texts))
}

func TestShutdown_WaitsForSessionsToClose(t *testing.T) {
	a := require.New(t)
	peerErr := make(chan error, 1)
	m := chatWith(t, modeDirectDial, func(t *kamune.Transport) error {
		_, _, err := t.ReceivePayload()
		peerErr <- err
		return nil
	})

	a.True(m.shutdown(time.Minute))
	a.Nil(m.sess)
	a.ErrorIs(waitFor(t, peerErr), kamune.ErrPeerDisconnected)
}

func TestChat_EscInServeModeClosesGracefully(t *testing.T) {
	a := require.New(t)
	m := newTestModel()
	m.store = openTestStore(t)
	m.mode = modeDirectServe
	m.state = stateConnecting
	m.att = newAttempt()
	att := m.att
	accept := func(*storage.Storage, *storage.Peer) error { return nil }
	clientNet, serverNet := net.Pipe()
	delivered := make(chan connectedMsg, 1)
	handlerDone := make(chan struct{})
	srv, err := serve("", m.store, accept,
		func(t *kamune.Transport, release chan struct{}) {
			delivered <- connectedMsg{
				att: att, transport: t, release: release,
			}
			go func() {
				<-release
				close(handlerDone)
			}()
		},
		func(error) {},
		kamune.ServeWithListener(newPipeListener(serverNet)),
	)
	a.NoError(err)
	m.srv = srv
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

	m.Update(waitFor(t, delivered))
	a.Equal(stateChat, m.state)
	sid := m.sess.t.SessionID()
	_, err = m.store.PopList(sid, storage.ResumptionTokensKey)
	a.NoError(err, "the session has no resumption tokens to begin with")

	peerErr := make(chan error, 1)
	go func() {
		_, _, err := client.ReceivePayload()
		peerErr <- err
	}()
	m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	a.Equal(stateWelcome, m.state)
	// The close frame goes out before the handler lets the connection
	// go, so the peer sees a graceful close.
	a.ErrorIs(waitFor(t, peerErr), kamune.ErrPeerDisconnected)
	waitFor(t, handlerDone)
	a.True(m.shutdown(time.Minute))
	_, err = m.store.PopList(sid, storage.ResumptionTokensKey)
	a.Error(err, "the closed session can still be resumed")
}

func TestSendPing(t *testing.T) {
	tests := []struct {
		name string
		// peer runs on the other side of the session.
		peer    func(*kamune.Transport) error
		timeout time.Duration
		wantErr error
	}{
		{
			name: "answered",
			peer: func(t *kamune.Transport) error {
				receiveLoop(t, make(chan []byte, 1), func(tea.Msg) {})
				return nil
			},
			timeout: time.Minute,
		},
		{
			name: "not answered",
			peer: func(t *kamune.Transport) error {
				for {
					if _, _, err := t.ReceivePayload(); err != nil {
						return nil
					}
				}
			},
			timeout: 100 * time.Millisecond,
			wantErr: kamune.ErrReceiveTimeout,
		},
		{
			name: "answered with other data",
			peer: func(t *kamune.Transport) error {
				if _, _, err := t.ReceivePayload(); err != nil {
					return err
				}
				_, err := t.Send(
					kamune.Bytes([]byte("other")), kamune.RoutePong,
				)
				if err != nil {
					return err
				}
				for {
					if _, _, err := t.ReceivePayload(); err != nil {
						return nil
					}
				}
			},
			timeout: time.Minute,
			wantErr: kamune.ErrVerificationFailed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			tr := dialPipe(t, tt.peer)
			pongCh := make(chan []byte, 1)
			go receiveLoop(tr, pongCh, func(tea.Msg) {})

			err := tuiSendPing(tr, pongCh, tt.timeout)
			if tt.wantErr == nil {
				a.NoError(err)
				return
			}
			a.ErrorIs(err, tt.wantErr)
		})
	}
}
