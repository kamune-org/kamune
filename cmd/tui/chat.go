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
			m.refreshChat()
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
			metadata, err := m.sess.t.Send(
				kamune.Bytes([]byte(text)), kamune.RouteExchangeMessages,
			)
			if err != nil {
				m.messages = append(m.messages,
					noticeLine(m.s.err, "Send error: "+err.Error()),
				)
				m.refreshChat()
				return m, tiCmd
			}
			m.messages = append(m.messages, messageLine(
				storage.SenderLocal, metadata.Timestamp(), text,
			))
			if err := m.store.AddChatEntry(
				m.sess.t.SessionID(),
				[]byte(text),
				metadata.Timestamp(),
				storage.SenderLocal,
			); err != nil {
				slog.Error("failed to persist sent chat entry",
					slog.String("session_id", m.sess.t.SessionID()),
					slog.Any("error", err),
				)
				m.messages = append(m.messages, notSavedLine(m.s, err))
			}
			m.refreshChat()
			m.ta.Reset()
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
