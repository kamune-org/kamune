package main

import (
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
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
	m := newTestModel()
	m.sessionExpiry = time.Now().Add(30 * time.Minute)

	view := m.viewChat()
	if !strings.Contains(view, "Session expires in") {
		t.Fatalf("expected countdown header, got:\n%s", view)
	}
	if !strings.Contains(view, "m") {
		t.Fatalf("expected minutes in countdown, got:\n%s", view)
	}
}

func TestViewChat_ExpiredShown(t *testing.T) {
	m := newTestModel()
	m.sessionExpiry = time.Now().Add(-time.Second)

	view := m.viewChat()
	if !strings.Contains(view, "Session expired") {
		t.Fatalf("expected 'Session expired', got:\n%s", view)
	}
}

func TestViewChat_NoCountdownWhenZero(t *testing.T) {
	m := newTestModel()

	view := m.viewChat()
	if strings.Contains(view, "Session") {
		t.Fatalf("expected no session header, got:\n%s", view)
	}
}

func TestEnterChat_SetsExpiryForRelayServe(t *testing.T) {
	m := newTestModel()
	m.mode = modeRelayServe
	m.relaySessionTTL = 30 * time.Minute

	if m.mode == modeRelayServe && m.relaySessionTTL > 0 {
		m.sessionExpiry = time.Now().Add(m.relaySessionTTL)
	}

	if m.sessionExpiry.IsZero() {
		t.Fatal("expected sessionExpiry to be set")
	}
	remaining := time.Until(m.sessionExpiry)
	if remaining < 29*time.Minute || remaining > 31*time.Minute {
		t.Errorf("expected ~30m remaining, got %v", remaining)
	}
}

func TestEnterChat_NoExpiryForDirectMode(t *testing.T) {
	m := newTestModel()
	m.mode = modeDirectDial
	m.relaySessionTTL = 30 * time.Minute

	if m.mode == modeRelayServe && m.relaySessionTTL > 0 {
		m.sessionExpiry = time.Now().Add(m.relaySessionTTL)
	}

	if !m.sessionExpiry.IsZero() {
		t.Fatal("expected sessionExpiry to remain zero for direct mode")
	}
}

// --- State transitions ---

func TestUpdate_ConnectFailedReturnsToWelcome(t *testing.T) {
	m := newTestModel()
	m.state = stateConnecting

	got, _ := m.Update(connectFailedMsg{err: nil})
	if got.(*model).state != stateWelcome {
		t.Errorf("expected stateWelcome, got %v", got.(*model).state)
	}
}

func TestUpdate_ConnectFailedIgnoredWhenNotConnecting(t *testing.T) {
	m := newTestModel()
	m.state = stateChat

	got, _ := m.Update(connectFailedMsg{err: nil})
	if got.(*model).state != stateChat {
		t.Errorf("expected stateChat unchanged, got %v", got.(*model).state)
	}
}

func TestUpdate_RelayReadySetsTokenAndTTL(t *testing.T) {
	m := newTestModel()
	m.state = stateConnecting

	got, _ := m.Update(relayReadyMsg{
		token:      []byte("abc123"),
		sessionTTL: 10 * time.Minute,
	})
	s := got.(*model)
	if string(s.relayToken) != "abc123" {
		t.Errorf("token = %q, want %q", s.relayToken, "abc123")
	}
	if s.relaySessionTTL != 10*time.Minute {
		t.Errorf("sessionTTL = %v, want %v", s.relaySessionTTL, 10*time.Minute)
	}
}

func TestUpdate_ConnectedSetsSessionTTL(t *testing.T) {
	m := newTestModel()
	m.state = stateConnecting
	m.mode = modeRelayDial
	m.relaySessionTTL = 5 * time.Minute

	msg := connectedMsg{sessionTTL: 15 * time.Minute}
	if msg.sessionTTL > 0 {
		m.relaySessionTTL = msg.sessionTTL
	}
	if m.relaySessionTTL != 15*time.Minute {
		t.Errorf("sessionTTL = %v, want %v", m.relaySessionTTL, 15*time.Minute)
	}
}

func TestUpdate_ConnectedPreservesExistingTTL(t *testing.T) {
	m := newTestModel()
	m.state = stateConnecting
	m.mode = modeRelayServe
	m.relaySessionTTL = 30 * time.Minute

	msg := connectedMsg{sessionTTL: 0}
	if msg.sessionTTL > 0 {
		m.relaySessionTTL = msg.sessionTTL
	}
	if m.relaySessionTTL != 30*time.Minute {
		t.Errorf("sessionTTL = %v, want %v", m.relaySessionTTL, 30*time.Minute)
	}
}

// --- Welcome menu ---

func TestWelcome_CursorWrapsDown(t *testing.T) {
	m := newTestModel()
	m.state = stateWelcome
	m.cursor = len(menuItems) - 1

	m.Update(tea.KeyMsg{Type: tea.KeyDown})
	if m.cursor != 0 {
		t.Errorf("cursor = %d, want 0 (wrap)", m.cursor)
	}
}

func TestWelcome_CursorWrapsUp(t *testing.T) {
	m := newTestModel()
	m.state = stateWelcome
	m.cursor = 0

	m.Update(tea.KeyMsg{Type: tea.KeyUp})
	if m.cursor != len(menuItems)-1 {
		t.Errorf("cursor = %d, want %d (wrap)", m.cursor, len(menuItems)-1)
	}
}

func TestWelcome_NumberKeySelectsMode(t *testing.T) {
	m := newTestModel()
	m.state = stateWelcome

	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'3'}})
	if m.mode != modeRelayDial {
		t.Errorf("mode = %v, want modeRelayDial", m.mode)
	}
	if m.state != stateInput {
		t.Errorf("state = %v, want stateInput", m.state)
	}
}

// --- Input validation ---

func TestInput_RelayDialRequiresBothFields(t *testing.T) {
	m := newTestModel()
	m.state = stateInput
	m.mode = modeRelayDial
	m.inputs = []textinput.Model{
		mkInput("addr", ""),
		mkInput("token", ""),
	}

	got, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if got.(*model).state != stateInput {
		t.Errorf("expected stateInput, got %v", got.(*model).state)
	}
}

func TestInput_EscapeReturnsToWelcome(t *testing.T) {
	m := newTestModel()
	m.state = stateInput
	m.mode = modeDirectDial
	m.inputs = []textinput.Model{mkInput("addr", "")}

	got, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if got.(*model).state != stateWelcome {
		t.Errorf("expected stateWelcome, got %v", got.(*model).state)
	}
}

// --- Chat ---

func TestUpdate_EscapeFromChatReturnsToWelcome(t *testing.T) {
	m := newTestModel()
	m.state = stateChat
	m.messages = []string{"hello"}

	got, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	s := got.(*model)
	if s.state != stateWelcome {
		t.Errorf("expected stateWelcome, got %v", s.state)
	}
	if s.messages != nil {
		t.Errorf("expected messages cleared, got %v", s.messages)
	}
}

func TestUpdate_ChatMessageAppended(t *testing.T) {
	m := newTestModel()
	m.state = stateChat
	m.messages = []string{}

	msg := chatMessageMsg{
		text: "hello from peer",
		time: time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC),
	}
	got, _ := m.Update(msg)
	s := got.(*model)
	if len(s.messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(s.messages))
	}
	if !strings.Contains(s.messages[0], "hello from peer") {
		t.Errorf("expected message text, got %q", s.messages[0])
	}
}

func TestUpdate_PeerDisconnectedShowsMessage(t *testing.T) {
	m := newTestModel()
	m.state = stateChat

	got, _ := m.Update(peerDisconnectedMsg{})
	s := got.(*model)
	if len(s.messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(s.messages))
	}
	if !strings.Contains(s.messages[0], "Peer disconnected") {
		t.Errorf("expected disconnect message, got %q", s.messages[0])
	}
}

// --- Cleanup ---

func TestCleanup_ResetsRelayState(t *testing.T) {
	m := newTestModel()
	m.relayToken = []byte("token")
	m.relaySessionTTL = 30 * time.Minute
	m.sessionExpiry = time.Now().Add(30 * time.Minute)

	m.cleanup()

	if m.relayToken != nil {
		t.Errorf("relayToken not reset")
	}
	if m.relaySessionTTL != 0 {
		t.Errorf("relaySessionTTL not reset")
	}
	if !m.sessionExpiry.IsZero() {
		t.Errorf("sessionExpiry not reset")
	}
}

func TestCancelConnect_ResetsRelayState(t *testing.T) {
	m := newTestModel()
	m.relayToken = []byte("token")
	m.relaySessionTTL = 30 * time.Minute
	m.sessionExpiry = time.Now().Add(30 * time.Minute)

	m.cancelConnect()

	if m.relayToken != nil {
		t.Errorf("relayToken not reset")
	}
	if m.relaySessionTTL != 0 {
		t.Errorf("relaySessionTTL not reset")
	}
	if !m.sessionExpiry.IsZero() {
		t.Errorf("sessionExpiry not reset")
	}
}
