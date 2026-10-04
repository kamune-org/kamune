package main

import (
	"fmt"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune"
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
	m.Update(connectedMsg{transport: dialPipe(t, handler)})
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
