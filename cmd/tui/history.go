package main

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/kamune-org/kamune/pkg/storage"
)

func (m *model) updateHistory(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyEsc:
			if m.histViewing {
				m.histViewing = false
				m.histMsgs = nil
				return m, nil
			}
			m.state = stateWelcome
			return m, nil
		case tea.KeyUp:
			if !m.histViewing && m.histCursor > 0 {
				m.histCursor--
			}
		case tea.KeyDown:
			if !m.histViewing && m.histCursor < len(m.sessions)-1 {
				m.histCursor++
			}
		case tea.KeyEnter:
			if !m.histViewing && len(m.sessions) > 0 {
				return m, loadSessionMessages(m.store, m.sessions[m.histCursor].ID)
			}
		case tea.KeyRunes:
			ch := msg.String()
			if ch == "k" && !m.histViewing && m.histCursor > 0 {
				m.histCursor--
			} else if ch == "j" && !m.histViewing && m.histCursor < len(m.sessions)-1 {
				m.histCursor++
			} else if ch == "q" && !m.histViewing {
				m.state = stateWelcome
				return m, nil
			}
		}

	case tea.WindowSizeMsg:
		if m.histViewing && m.histVP.Width > 0 {
			m.histVP.Width = msg.Width - 2
			m.histVP.Height = msg.Height - 4
		}
	}

	if m.histViewing {
		var vpCmd tea.Cmd
		m.histVP, vpCmd = m.histVP.Update(msg)
		return m, vpCmd
	}

	return m, nil
}

func (m *model) viewHistory() string {
	if m.histViewing {
		return m.viewHistoryMessages()
	}
	return m.viewHistoryList()
}

func (m *model) viewHistoryList() string {
	var b strings.Builder
	b.WriteString(m.s.title.Render(" Chat History"))
	b.WriteString("\n\n")

	if len(m.sessions) == 0 {
		b.WriteString(m.s.muted.Render("No chat history found."))
		b.WriteString("\n\n" + m.s.muted.Render("[Esc] back"))
		return lipgloss.NewStyle().Padding(1, 2).Render(b.String())
	}

	for i, s := range m.sessions {
		cursor := "  "
		if i == m.histCursor {
			cursor = "▸ "
		}
		sid := s.ID
		if len(sid) > 16 {
			sid = sid[:16] + "..."
		}
		name := s.Name
		if name == "" {
			name = sid
		}
		count := fmt.Sprintf("%d msgs", s.MessageCount)
		lastSeen := s.LastMessage.Format(time.DateTime)
		line := fmt.Sprintf("%s%s  %s  %s",
			cursor, m.s.bold.Render(name),
			m.s.muted.Render(count),
			m.s.muted.Render(lastSeen),
		)
		b.WriteString(line + "\n")
	}

	b.WriteString("\n" + m.s.muted.Render("[Enter] view  [Esc/q] back"))
	return lipgloss.NewStyle().Padding(1, 2).Render(b.String())
}

func (m *model) viewHistoryMessages() string {
	return m.histVP.View()
}

func loadSessionMessages(store *storage.Storage, sessionID string) tea.Cmd {
	return func() tea.Msg {
		entries, err := store.GetChatHistory(sessionID)
		if err != nil {
			return historyMessagesMsg{
				sessionID: sessionID,
				messages:  []string{fmt.Sprintf("Error loading messages: %v", err)},
			}
		}

		var msgs []string
		for _, ent := range entries {
			sender := "You"
			if ent.Sender != storage.SenderLocal {
				sender = "Peer"
			}
			msgs = append(msgs, fmt.Sprintf(
				"[%s] %s: %s",
				ent.Timestamp.Format(time.DateTime),
				sender,
				string(ent.Data),
			))
		}
		if len(msgs) == 0 {
			msgs = []string{"(no messages)"}
		}
		return historyMessagesMsg{
			sessionID: sessionID,
			messages:  msgs,
		}
	}
}
