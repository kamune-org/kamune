package main

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/kamune-org/kamune/pkg/storage"
)

func (m *model) updateChat(msg tea.Msg) (tea.Model, tea.Cmd) {
	var tiCmd tea.Cmd
	var vpCmd tea.Cmd

	m.ta, tiCmd = m.ta.Update(msg)
	m.vp, vpCmd = m.vp.Update(msg)

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.vp.Width = msg.Width
		m.ta.SetWidth(msg.Width)
		m.vp.Height = msg.Height - m.ta.Height() - lipgloss.Height("\n\n")
		if len(m.messages) > 0 {
			m.refreshChat()
		}
		m.vp.GotoBottom()

	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyEsc:
			m.cleanup()
			m.clearTranscript()
			m.state = stateWelcome
			return m, nil
		case tea.KeyEnter:
			text := m.ta.Value()
			if strings.TrimSpace(text) == "" || m.sess == nil {
				return m, tiCmd
			}
			// writeLoop sends it; sentMsg brings back the result.
			select {
			case m.sess.outbox <- text:
				m.ta.Reset()
			default:
				m.addLines(noticeLine(m.s.err,
					"Not sent: too many messages are still on their way. "+
						"Try again shortly.",
				))
			}
		}
	}

	return m, tea.Batch(tiCmd, vpCmd)
}

func (m *model) viewChat() string {
	var header string
	if !m.sessionExpiry.IsZero() {
		remaining := time.Until(m.sessionExpiry)
		if remaining > 0 {
			header = m.s.muted.Render(fmt.Sprintf("Session expires in %s", remaining.Round(time.Second))) + "\n"
		} else {
			header = m.s.err.Render("Session expired") + "\n"
		}
	}
	return header + m.vp.View() + "\n\n" + m.ta.View()
}

// handleSent shows the message that writeLoop sent and added to the
// history, or why it could not send it.
func (m *model) handleSent(msg sentMsg) {
	if msg.err != nil {
		m.addLines(noticeLine(m.s.err, "Send error: "+msg.err.Error()))
		return
	}
	lines := []chatLine{messageLine(storage.SenderLocal, msg.at, msg.text)}
	if msg.saveErr != nil {
		lines = append(lines, notSavedLine(m.s, msg.saveErr))
	}
	m.addLines(lines...)
}
