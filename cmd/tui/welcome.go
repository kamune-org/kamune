package main

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/kamune-org/kamune/pkg/storage"
)

func (m *model) updateWelcome(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyUp:
			m.cursor = (m.cursor - 1 + len(menuItems)) % len(menuItems)
		case tea.KeyDown:
			m.cursor = (m.cursor + 1) % len(menuItems)
		case tea.KeyEnter:
			return m.selectMode(m.cursor)
		case tea.KeyRunes:
			ch := msg.String()
			switch {
			case ch == "k":
				m.cursor = (m.cursor - 1 + len(menuItems)) % len(menuItems)
			case ch == "j":
				m.cursor = (m.cursor + 1) % len(menuItems)
			case ch >= "1" && ch <= "6":
				idx := int(ch[0] - '1')
				return m.selectMode(idx)
			}
		case tea.KeyTab:
			m.cursor = (m.cursor + 1) % len(menuItems)
		}
	}
	return m, nil
}

func (m *model) selectMode(idx int) (tea.Model, tea.Cmd) {
	switch idx {
	case 0:
		m.mode = modeDirectDial
		m.inputs = []textinput.Model{mkInput("Address (host:port)", "localhost:9000")}
	case 1:
		m.mode = modeDirectServe
		m.inputs = []textinput.Model{mkInput("Address (host:port)", ":9000")}
	case 2:
		m.mode = modeRelayDial
		m.inputs = []textinput.Model{
			mkInput("Relay address (host:port)", "localhost:9001"),
			mkInput("Token (hex)", ""),
		}
	case 3:
		m.mode = modeRelayServe
		m.inputs = []textinput.Model{
			mkInput("Relay address (host:port)", "localhost:9001"),
		}
	case 4:
		return m, loadSessions(m.store)
	case 5:
		return m, tea.Quit
	}
	m.state = stateInput
	m.connectErr = nil
	if len(m.inputs) > 0 {
		return m, m.focusInput(0)
	}
	return m, nil
}

func mkInput(placeholder, defaultVal string) textinput.Model {
	ti := textinput.New()
	ti.Placeholder = placeholder
	ti.SetValue(defaultVal)
	ti.CharLimit = 200
	ti.Width = 50
	return ti
}

func (m *model) viewWelcome() string {
	var b strings.Builder
	b.WriteString(m.s.title.Render(" Kamune Chat (TUI)"))
	b.WriteString("\n\n")

	for i, item := range menuItems {
		cursor := "  "
		style := m.s.muted
		if i == m.cursor {
			cursor = "▸ "
			style = m.s.bold
		}
		num := m.s.muted.Render(fmt.Sprintf("(%d)", i+1))
		b.WriteString(fmt.Sprintf("%s%s %s\n", cursor, num, style.Render(item)))
	}

	if m.connectErr != nil {
		b.WriteString("\n" + m.s.err.Render(
			"Error: "+sanitizeText(m.connectErr.Error()),
		))
	}

	b.WriteString("\n\n  Select with ↑↓ or number key")
	return lipgloss.NewStyle().Padding(1, 2).Render(b.String())
}

func (m *model) updateInput(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyEsc:
			m.state = stateWelcome
			return m, nil
		case tea.KeyEnter:
			if m.mode == modeRelayDial {
				if m.inputs[0].Value() == "" || m.inputs[1].Value() == "" {
					return m, nil
				}
			} else if m.inputs[0].Value() == "" {
				return m, nil
			}
			m.state = stateConnecting
			return m, m.startConnect()
		case tea.KeyTab:
			return m, m.focusInput(nextInput(m.inputs))
		case tea.KeyShiftTab:
			return m, m.focusInput(prevInput(m.inputs))
		}
	}

	cmd := m.updateInputs(msg)
	return m, cmd
}

// focusInput focuses the input at i and blurs every other one. An input
// takes keys while it is focused, so only one may be.
func (m *model) focusInput(i int) tea.Cmd {
	for j := range m.inputs {
		m.inputs[j].Blur()
	}
	return m.inputs[i].Focus()
}

func nextInput(inputs []textinput.Model) int {
	for i := range inputs {
		if inputs[i].Focused() {
			return (i + 1) % len(inputs)
		}
	}
	return 0
}

func prevInput(inputs []textinput.Model) int {
	for i := range inputs {
		if inputs[i].Focused() {
			return (i - 1 + len(inputs)) % len(inputs)
		}
	}
	return 0
}

func (m *model) updateInputs(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	for i := range m.inputs {
		m.inputs[i], cmd = m.inputs[i].Update(msg)
	}
	return cmd
}

func (m *model) viewInput() string {
	var b strings.Builder

	modeLabel := ""
	switch m.mode {
	case modeDirectDial:
		modeLabel = "Direct Connect"
	case modeDirectServe:
		modeLabel = "Start Server"
	case modeRelayDial:
		modeLabel = "Connect via Relay"
	case modeRelayServe:
		modeLabel = "Start Relay Server"
	}

	b.WriteString(m.s.title.Render(" " + modeLabel))
	b.WriteString("\n\n")

	for i, ti := range m.inputs {
		b.WriteString(ti.View())
		b.WriteString("\n")
		if i < len(m.inputs)-1 {
			_ = i // just separator between inputs
		}
	}

	b.WriteString("\n" + m.s.muted.Render("[Enter] connect  [Esc] back  [Tab] next field"))
	return lipgloss.NewStyle().Padding(1, 2).Render(b.String())
}

func (m *model) updateConnecting(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.Type == tea.KeyEsc {
			m.cancelConnect()
			m.state = stateWelcome
			return m, nil
		}
	}
	return m, nil
}

func (m *model) viewConnecting() string {
	var b strings.Builder
	b.WriteString(m.s.title.Render(" Connecting..."))
	b.WriteString("\n\n")

	label := ""
	switch m.mode {
	case modeDirectDial:
		label = "Dialing " + m.inputs[0].Value()
	case modeDirectServe:
		label = "Listening on " + m.inputs[0].Value()
	case modeRelayDial:
		label = "Connecting via relay " + m.inputs[0].Value()
	case modeRelayServe:
		label = "Relay server on " + m.inputs[0].Value()
		if m.relayToken != nil {
			tokenHex := fmt.Sprintf("%x", m.relayToken)
			label += "\n\nToken: " + m.s.highlight.Render(tokenHex)
			label += "\n\n" + m.s.muted.Render("Share this token with your peer.")
		}
	}
	b.WriteString(label)
	if m.connectErr != nil {
		// A server keeps listening after a peer is rejected; say why
		// the last one was.
		b.WriteString("\n\n" + m.s.err.Render(
			"Error: "+sanitizeText(m.connectErr.Error()),
		))
	}

	b.WriteString("\n\n" + m.s.muted.Render("[Esc] cancel"))
	return lipgloss.NewStyle().Padding(1, 2).Render(b.String())
}

// updateVerify answers the verify prompt. Only "y" or "Y" accepts the
// peer; "n", "N" and Esc reject it. Every other key, Enter among them, is
// ignored, so an Enter meant for the previous screen cannot approve a key
// the user has not looked at.
func (m *model) updateVerify(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	var accept bool
	switch {
	case key.Type == tea.KeyEsc:
	case key.Type != tea.KeyRunes || key.Paste:
		return m, nil
	case key.String() == "y" || key.String() == "Y":
		accept = true
	case key.String() == "n" || key.String() == "N":
	default:
		return m, nil
	}

	m.connectErr = nil
	if accept {
		answer(m.verifyReq.responseCh, nil)
		m.verifyReq = nil
		m.state = stateConnecting
		return m, nil
	}

	err := fmt.Errorf("peer verification rejected")
	answer(m.verifyReq.responseCh, err)
	m.verifyReq = nil
	if m.mode == modeDirectServe || m.mode == modeRelayServe {
		// A server goes on waiting for a peer.
		m.state = stateConnecting
		return m, nil
	}
	m.cancelConnect()
	m.state = stateWelcome
	m.connectErr = err
	return m, nil
}

func (m *model) viewVerify() string {
	var b strings.Builder
	b.WriteString(m.s.title.Render(" Verify Peer Identity"))
	b.WriteString("\n\n")

	req := m.verifyReq
	if req == nil {
		return ""
	}

	// The fingerprints and the local verdict come first: the name and the
	// version are the peer's own claims, so they go below them, each on a
	// line of its own.
	b.WriteString("Peer's numeric fingerprint:\n  " +
		m.s.highlight.Render(req.numericFP))
	if req.localNumericFP != "" {
		b.WriteString("\nYour numeric fingerprint:\n  " + req.localNumericFP)
	}
	// Not every app shows a numeric fingerprint; bus and the daemon show
	// the hex one.
	b.WriteString("\n" + m.s.muted.Render(
		"Over a channel you trust, ask the peer to read out the numeric\n"+
			"fingerprint of its own key, and check it against the peer's\n"+
			"number above. If its app shows no numeric fingerprint, compare\n"+
			"the hex fingerprint instead.",
	))
	b.WriteString("\n\nEmoji fingerprint:\n  " + req.emojiFP)
	b.WriteString("\n\nHex fingerprint:\n  " + m.s.muted.Render(req.hexFP))

	if req.isNew {
		b.WriteString("\n\n" + m.s.highlight.Render(
			"⚠ This peer is not known to you.",
		))
	} else {
		b.WriteString("\n\n" + m.s.good.Render(
			"✓ This peer has connected before.",
		))
		b.WriteString("\nStored name: " + m.s.bold.Render(
			displayName(req.knownName),
		))
	}

	b.WriteString("\n\nClaimed name (unverified): " + m.s.bold.Render(
		displayName(req.peer.Name),
	))
	b.WriteString("\nApp version: " + displayVersion(req.peer.AppVersion))

	b.WriteString("\n\n  [Y] Accept  [N/Esc] Reject")
	return lipgloss.NewStyle().Padding(1, 2).Render(b.String())
}

func loadSessions(store *storage.Storage) tea.Cmd {
	return func() tea.Msg {
		sessions, err := store.ListSessionsByRecent()
		if err != nil {
			return historySessionsMsg{err: err}
		}
		return historySessionsMsg{sessions: sessions}
	}
}
