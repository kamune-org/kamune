package main

import (
	"bytes"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/storage"
)

// logOnStart logs a record as the UI starts and then quits.
type logOnStart struct{}

func (logOnStart) Init() tea.Cmd {
	return func() tea.Msg {
		slog.Error("serve conn", slog.String("error", "handshake failed"))
		return tea.QuitMsg{}
	}
}

func (m logOnStart) Update(tea.Msg) (tea.Model, tea.Cmd) { return m, nil }

func (logOnStart) View() string { return "" }

func TestRunUI_KeepsLogsOffTheTerminal(t *testing.T) {
	tests := []struct {
		name    string
		logFile bool
	}{
		{"dropped", false},
		{"to a file", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			// The default slog handler writes through the log package, to
			// stderr unless told otherwise; catch what it would print.
			prevLogger := slog.Default()
			prevOut, prevFlags := log.Writer(), log.Flags()
			var stderr bytes.Buffer
			log.SetOutput(&stderr)
			t.Cleanup(func() {
				slog.SetDefault(prevLogger)
				log.SetOutput(prevOut)
				log.SetFlags(prevFlags)
			})

			var path string
			if tt.logFile {
				path = filepath.Join(t.TempDir(), "tui.log")
			}
			var screen bytes.Buffer
			p := tea.NewProgram(logOnStart{},
				tea.WithInput(nil),
				tea.WithOutput(&screen),
				tea.WithoutSignalHandler(),
			)
			a.NoError(runUI(p, path))

			a.NotContains(stderr.String(), "serve conn")
			a.NotContains(screen.String(), "serve conn")
			// The logger from before is back, and so is the output of the
			// log package, which it writes through.
			a.Same(prevLogger, slog.Default())
			a.Same(&stderr, log.Writer())
			a.Equal(prevFlags, log.Flags())
			slog.Info("after the ui")
			a.Contains(stderr.String(), "after the ui")
			if tt.logFile {
				data, err := os.ReadFile(path)
				a.NoError(err)
				a.Contains(string(data), "serve conn")
				info, err := os.Stat(path)
				a.NoError(err)
				a.Zero(info.Mode().Perm() & 0o077)
			}
		})
	}
}

func TestHandleChatMessage_ReportsUnsavedMessage(t *testing.T) {
	a := require.New(t)
	m := newTestModel()
	m.state = stateChat
	m.transport = dialPipe(t, func(*kamune.Transport) error { return nil })
	m.store = openTestStore(t)
	a.NoError(m.store.Close())

	m.Update(chatMessageMsg{sender: storage.SenderPeer, text: "hello"})
	a.Len(m.messages, 2)
	a.Equal("hello", m.messages[0].text)
	a.Contains(m.messages[1].text, "not saved to history")
	a.Contains(m.vp.View(), "not saved to history")
}
