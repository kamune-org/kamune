package main

import (
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/require"
)

func newTestModel() *model {
	return &model{
		send: func(tea.Msg) {},
		s:    defaultStyles(),
		vp:   viewport.New(80, 24),
		ta:   textarea.New(),
	}
}

// --- Session TTL countdown ---

func TestViewChat_CountdownShown(t *testing.T) {
	a := require.New(t)
	m := newTestModel()
	m.sessionExpiry = time.Now().Add(30 * time.Minute)

	view := m.viewChat()
	a.Contains(view, "Session expires in")
	a.Contains(view, "m")
}

func TestViewChat_ExpiredShown(t *testing.T) {
	a := require.New(t)
	m := newTestModel()
	m.sessionExpiry = time.Now().Add(-time.Second)

	view := m.viewChat()
	a.Contains(view, "Session expired")
}

func TestViewChat_NoCountdownWhenZero(t *testing.T) {
	a := require.New(t)
	m := newTestModel()

	view := m.viewChat()
	a.NotContains(view, "Session")
}

// connectInMode starts a chat in mode for a session that a connection
// attempt delivers with msg, after the relay server of the attempt, if
// ready is set, has registered. It returns the model, and the times just
// before and just after the session was delivered.
func connectInMode(
	t *testing.T, mode inputMode, ready *relayReadyMsg, msg connectedMsg,
) (m *model, before, after time.Time) {
	t.Helper()
	a := require.New(t)
	m = newTestModel()
	m.store = openTestStore(t)
	m.mode = mode
	m.state = stateConnecting
	m.att = newAttempt()
	if ready != nil {
		srv, _ := idleServer(t, m.store)
		t.Cleanup(func() { _ = srv.Close() })
		ready.att = m.att
		ready.srv = srv
		m.Update(*ready)
	}
	msg.att = m.att
	msg.transport, _ = peerSession(t)
	before = time.Now()
	m.Update(msg)
	after = time.Now()
	a.Equal(stateChat, m.state)
	return m, before, after
}

func TestConnected_SessionTTLAndExpiry(t *testing.T) {
	tests := []struct {
		name  string
		mode  inputMode
		ready *relayReadyMsg
		msg   connectedMsg
		// ttl is the session TTL that the model should keep, and
		// expires whether the chat should show a countdown.
		ttl     time.Duration
		expires bool
	}{
		{
			name:    "relay serve",
			mode:    modeRelayServe,
			ready:   &relayReadyMsg{sessionTTL: 30 * time.Minute},
			ttl:     30 * time.Minute,
			expires: true,
		},
		{
			name: "relay dial",
			mode: modeRelayDial,
			msg:  connectedMsg{sessionTTL: 15 * time.Minute},
			ttl:  15 * time.Minute,
		},
		{name: "direct dial", mode: modeDirectDial},
		{name: "direct serve", mode: modeDirectServe},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			m, before, after := connectInMode(t, tt.mode, tt.ready, tt.msg)
			a.Equal(tt.ttl, m.relaySessionTTL)
			if !tt.expires {
				a.True(m.sessionExpiry.IsZero(), "expiry %v", m.sessionExpiry)
				return
			}
			a.WithinRange(m.sessionExpiry, before.Add(tt.ttl), after.Add(tt.ttl))
		})
	}
}

// --- State transitions ---

func TestUpdate_ConnectFailedReturnsToWelcome(t *testing.T) {
	a := require.New(t)
	m := newTestModel()
	m.state = stateConnecting

	got, _ := m.Update(connectFailedMsg{err: nil})
	a.Equal(stateWelcome, got.(*model).state)
}

func TestUpdate_ConnectFailedIgnoredWhenNotConnecting(t *testing.T) {
	a := require.New(t)
	m := newTestModel()
	m.state = stateChat

	got, _ := m.Update(connectFailedMsg{err: nil})
	a.Equal(stateChat, got.(*model).state)
}

func TestUpdate_RelayReadySetsTokenAndTTL(t *testing.T) {
	a := require.New(t)
	m := newTestModel()
	m.state = stateConnecting

	got, _ := m.Update(relayReadyMsg{
		token:      []byte("abc123"),
		sessionTTL: 10 * time.Minute,
	})
	s := got.(*model)
	a.Equal("abc123", string(s.relayToken))
	a.Equal(10*time.Minute, s.relaySessionTTL)
}

// --- Welcome menu ---

func TestWelcome_CursorWrapsDown(t *testing.T) {
	a := require.New(t)
	m := newTestModel()
	m.state = stateWelcome
	m.cursor = len(menuItems) - 1

	m.Update(tea.KeyMsg{Type: tea.KeyDown})
	a.Equal(0, m.cursor)
}

func TestWelcome_CursorWrapsUp(t *testing.T) {
	a := require.New(t)
	m := newTestModel()
	m.state = stateWelcome
	m.cursor = 0

	m.Update(tea.KeyMsg{Type: tea.KeyUp})
	a.Equal(len(menuItems)-1, m.cursor)
}

func TestWelcome_NumberKeySelectsMode(t *testing.T) {
	a := require.New(t)
	m := newTestModel()
	m.state = stateWelcome

	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'3'}})
	a.Equal(modeRelayDial, m.mode)
	a.Equal(stateInput, m.state)
}

// --- Input validation ---

func TestInput_RelayDialRequiresBothFields(t *testing.T) {
	a := require.New(t)
	m := newTestModel()
	m.state = stateInput
	m.mode = modeRelayDial
	m.inputs = []textinput.Model{
		mkInput("addr", ""),
		mkInput("token", ""),
	}

	got, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	a.Equal(stateInput, got.(*model).state)
}

func TestInput_TabMovesFocus(t *testing.T) {
	tab := tea.KeyMsg{Type: tea.KeyTab}
	shiftTab := tea.KeyMsg{Type: tea.KeyShiftTab}
	tests := []struct {
		name string
		keys []tea.KeyMsg
		// field is the input that should get the typed text.
		field int
	}{
		{"no tab", nil, 0},
		{"tab", []tea.KeyMsg{tab}, 1},
		{"tab wraps", []tea.KeyMsg{tab, tab}, 0},
		{"shift+tab", []tea.KeyMsg{tab, shiftTab}, 0},
		{"shift+tab wraps", []tea.KeyMsg{shiftTab}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			m := newTestModel()
			m.state = stateWelcome
			m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'3'}})
			a.Equal(modeRelayDial, m.mode)
			want := make([]string, len(m.inputs))
			for i := range m.inputs {
				want[i] = m.inputs[i].Value()
			}

			for _, k := range tt.keys {
				m.Update(k)
			}
			m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("abcd")})
			want[tt.field] += "abcd"
			for i := range m.inputs {
				a.Equal(want[i], m.inputs[i].Value(), "field %d", i)
				a.Equal(i == tt.field, m.inputs[i].Focused(), "field %d", i)
			}
		})
	}
}

func TestInput_RelayAddress(t *testing.T) {
	tests := []struct {
		name  string
		addr  string
		valid bool
		warns bool
	}{
		{"default", "", true, false},
		{"tls", "tls://relay.example:8890", true, false},
		{"ws", "ws://relay.example:8888", true, true},
		{"tcp", "tcp://relay.example:8889", true, true},
		{"unknown scheme", "http://relay.example", false, false},
		{"path", "wss://relay.example/ws", false, false},
	}
	for _, mode := range []rune{'3', '4'} {
		for _, tt := range tests {
			t.Run(string(mode)+" "+tt.name, func(t *testing.T) {
				a := require.New(t)
				m := newTestModel()
				m.state = stateWelcome
				m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{mode}})
				a.Equal(stateInput, m.state)
				if tt.addr == "" {
					a.True(strings.HasPrefix(m.inputs[0].Value(), "wss://"))
				} else {
					m.inputs[0].SetValue(tt.addr)
				}
				view := m.viewInput()
				a.Contains(view, "Relay address")
				a.Equal(tt.warns,
					strings.Contains(view, "does not authenticate the relay"))
				if tt.valid {
					return
				}

				if m.mode == modeRelayDial {
					m.inputs[1].SetValue("00ff")
				}
				m.Update(tea.KeyMsg{Type: tea.KeyEnter})
				a.Equal(stateInput, m.state)
				a.Nil(m.att)
				a.ErrorIs(m.connectErr, errRelayAddress)
				a.Contains(m.viewInput(), "invalid relay address")
				m.Update(tea.KeyMsg{Type: tea.KeyEsc})
				a.Equal(stateWelcome, m.state)
				a.Nil(m.connectErr)
			})
		}
	}
}

func TestInput_EscapeReturnsToWelcome(t *testing.T) {
	a := require.New(t)
	m := newTestModel()
	m.state = stateInput
	m.mode = modeDirectDial
	m.inputs = []textinput.Model{mkInput("addr", "")}

	got, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	a.Equal(stateWelcome, got.(*model).state)
}

// --- Chat ---

func TestUpdate_EscapeFromChatReturnsToWelcome(t *testing.T) {
	a := require.New(t)
	m := newTestModel()
	m.state = stateChat
	m.messages = []chatLine{noticeLine(m.s.muted, "hello")}

	got, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	s := got.(*model)
	a.Equal(stateWelcome, s.state)
	a.Nil(s.messages)
}

func TestUpdate_ChatMessageAppended(t *testing.T) {
	a := require.New(t)
	m := newTestModel()
	m.state = stateChat
	m.sess = &chatSession{}
	m.messages = []chatLine{}

	msg := chatMessageMsg{
		text: "hello from peer",
		time: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC),
	}
	got, _ := m.Update(sessionMsg{m.sess, msg})
	s := got.(*model)
	a.Len(s.messages, 1)
	a.Contains(s.messages[0].text, "hello from peer")
}

func TestUpdate_PeerDisconnectedShowsMessage(t *testing.T) {
	a := require.New(t)
	m := newTestModel()
	m.state = stateChat
	m.sess = &chatSession{}

	got, _ := m.Update(sessionMsg{m.sess, peerDisconnectedMsg{}})
	s := got.(*model)
	a.Len(s.messages, 1)
	a.Contains(s.messages[0].text, "Peer disconnected")
}

// --- Cleanup ---

func TestCleanup_ResetsRelayState(t *testing.T) {
	a := require.New(t)
	m := newTestModel()
	m.relayToken = []byte("token")
	m.relaySessionTTL = 30 * time.Minute
	m.sessionExpiry = time.Now().Add(30 * time.Minute)

	m.cleanup()

	a.Nil(m.relayToken, "relayToken not reset")
	a.Zero(m.relaySessionTTL, "relaySessionTTL not reset")
	a.True(m.sessionExpiry.IsZero(),
		"sessionExpiry not reset")
}

func TestCancelConnect_ResetsRelayState(t *testing.T) {
	a := require.New(t)
	m := newTestModel()
	m.relayToken = []byte("token")
	m.relaySessionTTL = 30 * time.Minute
	m.sessionExpiry = time.Now().Add(30 * time.Minute)

	m.cancelConnect()

	a.Nil(m.relayToken, "relayToken not reset")
	a.Zero(m.relaySessionTTL, "relaySessionTTL not reset")
	a.True(m.sessionExpiry.IsZero(),
		"sessionExpiry not reset")
}
