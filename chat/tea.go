package main

import (
	"fmt"
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
	vp.SetContent(fmt.Sprintf(`Session ID is %s. Happy Chatting!`, t.SessionID()))
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

func (m model) Init() tea.Cmd {
	return textarea.Blink
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var (
		tiCmd tea.Cmd
		vpCmd tea.Cmd
	)

	m.textarea, tiCmd = m.textarea.Update(msg)
	m.viewport, vpCmd = m.viewport.Update(msg)

	switch msg := msg.(type) {
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
			metadata, err := m.transport.Send(kamune.Bytes([]byte(text)))
			if err != nil {
				m.err = err
				return m, tiCmd
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
