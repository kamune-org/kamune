package main

import (
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
		s:  defaultStyles(),
		vp: viewport.New(80, 24),
		ta: textarea.New(),
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

func TestEnterChat_SetsExpiryForRelayServe(t *testing.T) {
	a := require.New(t)
	m := newTestModel()
	m.mode = modeRelayServe
	m.relaySessionTTL = 30 * time.Minute

	if m.mode == modeRelayServe && m.relaySessionTTL > 0 {
		m.sessionExpiry = time.Now().Add(m.relaySessionTTL)
	}

	a.False(m.sessionExpiry.IsZero(), "expected sessionExpiry to be set")
	remaining := time.Until(m.sessionExpiry)
	a.True(remaining >= 29*time.Minute && remaining <= 31*time.Minute, "expected ~30m remaining, got %v", remaining)
}

func TestEnterChat_NoExpiryForDirectMode(t *testing.T) {
	a := require.New(t)
	m := newTestModel()
	m.mode = modeDirectDial
	m.relaySessionTTL = 30 * time.Minute

	if m.mode == modeRelayServe && m.relaySessionTTL > 0 {
		m.sessionExpiry = time.Now().Add(m.relaySessionTTL)
	}

	a.True(m.sessionExpiry.IsZero(), "expected sessionExpiry to remain zero for direct mode")
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

func TestUpdate_ConnectedSetsSessionTTL(t *testing.T) {
	a := require.New(t)
	m := newTestModel()
	m.state = stateConnecting
	m.mode = modeRelayDial
	m.relaySessionTTL = 5 * time.Minute

	msg := connectedMsg{sessionTTL: 15 * time.Minute}
	if msg.sessionTTL > 0 {
		m.relaySessionTTL = msg.sessionTTL
	}
	a.Equal(15*time.Minute, m.relaySessionTTL)
}

func TestUpdate_ConnectedPreservesExistingTTL(t *testing.T) {
	a := require.New(t)
	m := newTestModel()
	m.state = stateConnecting
	m.mode = modeRelayServe
	m.relaySessionTTL = 30 * time.Minute

	msg := connectedMsg{sessionTTL: 0}
	if msg.sessionTTL > 0 {
		m.relaySessionTTL = msg.sessionTTL
	}
	a.Equal(30*time.Minute, m.relaySessionTTL)
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
	m.messages = []string{"hello"}

	got, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	s := got.(*model)
	a.Equal(stateWelcome, s.state)
	a.Nil(s.messages)
}

func TestUpdate_ChatMessageAppended(t *testing.T) {
	a := require.New(t)
	m := newTestModel()
	m.state = stateChat
	m.messages = []string{}

	msg := chatMessageMsg{
		text: "hello from peer",
		time: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC),
	}
	got, _ := m.Update(msg)
	s := got.(*model)
	a.Len(s.messages, 1)
	a.Contains(s.messages[0], "hello from peer")
}

func TestUpdate_PeerDisconnectedShowsMessage(t *testing.T) {
	a := require.New(t)
	m := newTestModel()
	m.state = stateChat

	got, _ := m.Update(peerDisconnectedMsg{})
	s := got.(*model)
	a.Len(s.messages, 1)
	a.Contains(s.messages[0], "Peer disconnected")
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
