package main

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/kamune-org/kamune"
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
			m.vp.SetContent(lipgloss.NewStyle().
				Width(m.vp.Width).
				Render(strings.Join(m.messages, "\n")),
			)
		}
		m.vp.GotoBottom()

	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyEsc:
			m.cleanup()
			m.messages = nil
			m.versionWarn = ""
			m.state = stateWelcome
			return m, nil
		case tea.KeyEnter:
			text := m.ta.Value()
			if strings.TrimSpace(text) == "" {
				return m, tiCmd
			}
			metadata, err := m.transport.Send(
				kamune.Bytes([]byte(text)), kamune.RouteExchangeMessages,
			)
			if err != nil {
				m.messages = append(m.messages, m.s.err.Render("Send error: "+err.Error()))
				m.vp.SetContent(lipgloss.NewStyle().
					Width(m.vp.Width).
					Render(strings.Join(m.messages, "\n")),
				)
				m.vp.GotoBottom()
				return m, tiCmd
			}
			if err := m.store.AddChatEntry(
				m.transport.SessionID(),
				[]byte(text),
				metadata.Timestamp(),
				storage.SenderLocal,
			); err != nil {
				slog.Error("failed to persist sent chat entry",
					slog.String("session_id", m.transport.SessionID()),
					slog.Any("error", err),
				)
			}
			prefix := fmt.Sprintf("[%s] You: ", metadata.Timestamp().Format(time.DateTime))
			m.messages = append(m.messages,
				m.s.userPrefix.Render(prefix)+m.s.userText.Render(text),
			)
			m.vp.SetContent(lipgloss.NewStyle().
				Width(m.vp.Width).
				Render(strings.Join(m.messages, "\n")),
			)
			m.ta.Reset()
			m.vp.GotoBottom()
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


