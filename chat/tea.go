package main

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/kamune-org/kamune"
)

const gap = "\n\n"

type (
	errMsg error
)

// historyLoaded is sent once the background goroutine finishes reading prior
// chat entries from the database.
type historyLoaded struct {
	messages []string
}

type model struct {
	viewport   viewport.Model
	messages   []string
	textarea   textarea.Model
	userPrefix lipgloss.Style
	userText   lipgloss.Style
	peerPrefix lipgloss.Style
	peerText   lipgloss.Style
	err        error
	transport  *kamune.Transport
}

func initialModel(t *kamune.Transport) model {
	ta := textarea.New()
	ta.Placeholder = "Send a message..."
	ta.Focus()
	ta.FocusedStyle = textarea.Style{
		Base: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#43BF6D")).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#383838")).
			Padding(0, 1),
		CursorLine: lipgloss.NewStyle(),
	}

	ta.Prompt = "┃ "
	ta.CharLimit = 280

	ta.SetWidth(30)
	ta.SetHeight(3)

	ta.ShowLineNumbers = false

	vp := viewport.New(30, 5)
	vp.SetContent(fmt.Sprintf(`Session ID is %s. Loading history…`, t.SessionID()))
	vp.MouseWheelEnabled = true
	vp.Style = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#383838")).
		Padding(0, 1)
	ta.KeyMap.InsertNewline.SetEnabled(false)

	return model{
		textarea:   ta,
		messages:   []string{},
		viewport:   vp,
		userPrefix: lipgloss.NewStyle().Foreground(lipgloss.Color("#4A90E2")),
		userText:   lipgloss.NewStyle().Foreground(lipgloss.Color("#E0F0FF")),
		peerPrefix: lipgloss.NewStyle().Foreground(lipgloss.Color("#FFA500")),
		peerText:   lipgloss.NewStyle().Foreground(lipgloss.Color("#FFF7E1")),
		err:        nil,
		transport:  t,
	}
}

// loadHistory returns a tea.Cmd that asynchronously reads prior chat entries
// from the database and delivers them as a historyLoaded message.
func loadHistory(t *kamune.Transport, userPrefix, userText, peerPrefix, peerText lipgloss.Style) tea.Cmd {
	return func() tea.Msg {
		entries, err := t.Store().GetChatHistory(t.SessionID())
		if err != nil {
			slog.Warn("failed to load chat history",
				slog.String("session_id", t.SessionID()),
				slog.Any("error", err))
			return historyLoaded{}
		}

		var msgs []string
		for _, ent := range entries {
			sender := "You"
			prefixStyle := userPrefix
			textStyle := userText
			if ent.Sender != kamune.SenderLocal {
				sender = "Peer"
				prefixStyle = peerPrefix
				textStyle = peerText
			}
			prefix := fmt.Sprintf("[%s] %s: ", ent.Timestamp.Format(time.DateTime), sender)
			msgs = append(msgs, prefixStyle.Render(prefix)+textStyle.Render(string(ent.Data)))
		}
		return historyLoaded{messages: msgs}
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(
		textarea.Blink,
		loadHistory(m.transport, m.userPrefix, m.userText, m.peerPrefix, m.peerText),
	)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var (
		tiCmd tea.Cmd
		vpCmd tea.Cmd
	)

	m.textarea, tiCmd = m.textarea.Update(msg)
	m.viewport, vpCmd = m.viewport.Update(msg)

	switch msg := msg.(type) {
	case historyLoaded:
		header := fmt.Sprintf("Session ID is %s. Happy Chatting!", m.transport.SessionID())
		if len(msg.messages) > 0 {
			header = fmt.Sprintf("Session ID is %s. Restored %d message(s). Happy Chatting!",
				m.transport.SessionID(), len(msg.messages))
			// Prepend historical messages before any that arrived while loading.
			m.messages = append(msg.messages, m.messages...)
		}
		content := header
		if len(m.messages) > 0 {
			content = header + "\n" + strings.Join(m.messages, "\n")
		}
		m.viewport.SetContent(lipgloss.
			NewStyle().
			Width(m.viewport.Width).
			Render(content),
		)
		m.viewport.GotoBottom()

	case tea.WindowSizeMsg:
		m.viewport.Width = msg.Width
		m.textarea.SetWidth(msg.Width)
		m.viewport.Height = msg.Height - m.textarea.Height() - lipgloss.Height(gap)

		if len(m.messages) > 0 {
			m.viewport.SetContent(lipgloss.
				NewStyle().
				Width(m.viewport.Width).
				Render(strings.Join(m.messages, "\n")),
			)
		}
		m.viewport.GotoBottom()
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC, tea.KeyEsc:
			return m, tea.Quit
		case tea.KeyEnter:
			text := m.textarea.Value()
			metadata, err := m.transport.Send(
				kamune.Bytes([]byte(text)), kamune.RouteExchangeMessages,
			)
			if err != nil {
				m.err = err
				return m, tiCmd
			}
			if err := m.transport.Store().AddChatEntry(
				m.transport.SessionID(),
				[]byte(text),
				metadata.Timestamp(),
				kamune.SenderLocal,
			); err != nil {
				slog.Error("failed to persist sent chat entry",
					slog.String("session_id", m.transport.SessionID()),
					slog.Any("error", err))
			}
			prefix := fmt.Sprintf(
				"[%s] You: ",
				metadata.Timestamp().Format(time.DateTime),
			)
			m.messages = append(
				m.messages,
				m.userPrefix.Render(prefix)+m.userText.Render(text),
			)
			m.viewport.SetContent(lipgloss.
				NewStyle().
				Width(m.viewport.Width).
				Render(strings.Join(m.messages, "\n")),
			)
			m.textarea.Reset()
			m.viewport.GotoBottom()
		}

	case Message:
		m.messages = append(
			m.messages,
			m.peerPrefix.Render(msg.prefix)+m.peerText.Render(msg.text),
		)
		m.viewport.SetContent(lipgloss.
			NewStyle().
			Width(m.viewport.Width).
			Render(strings.Join(m.messages, "\n")),
		)
		m.viewport.GotoBottom()

	case errMsg:
		m.err = msg
		return m, nil
	}

	return m, tea.Batch(tiCmd, vpCmd)
}

func (m model) View() string {
	return fmt.Sprintf(
		"%s%s%s",
		m.viewport.View(),
		gap,
		m.textarea.View(),
	)
}
