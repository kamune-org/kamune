package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/charmbracelet/lipgloss"
	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/pkg/storage"
)

// hostile is a chat message that tries to write the clipboard (OSC 52),
// retitle the window (OSC 0), show a link to another address (OSC 8), and
// forge a line from the local user in the user's colours.
const hostile = "hi\x1b]52;c;Y3VybCBldmlsfHNoCg==\x07" +
	"\x1b]0;pwned\x07" +
	"\x1b]8;;https://evil.example\x07click\x1b]8;;\x07" +
	"\n\x1b[38;2;74;144;226m[2026-10-03 10:00:00] You: \x1b[0mI agree"

func TestSanitizeText(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"plain", "hello", "hello"},
		{"persian with zwnj", "علی\u200Cرضا", "علی\u200Cرضا"},
		{"emoji with zwj", "👩\u200D💻", "👩\u200D💻"},
		{"bidi marks kept", "a\u200Fb\u200Ec", "a\u200Fb\u200Ec"},
		{"osc 52", "a\x1b]52;c;aGk=\x07b", "ab"},
		{"osc 0 with st", "a\x1b]0;title\x1b\\b", "ab"},
		{"unterminated osc", "a\x1b]0;title", "a"},
		{"sgr", "\x1b[31mred\x1b[0m", "red"},
		{"esc sequence", "a\x1bcb", "ab"},
		{"trailing esc", "a\x1b", "a"},
		{"c1 csi", "a\u009b31mb", "a31mb"},
		{"c0 and del", "a\x00\x07\x08\x7fb", "ab"},
		{"bidi override", "a\u202Eb\u202Cc", "abc"},
		{"bidi isolate", "a\u2066b\u2069c", "abc"},
		{"arabic letter mark kept", "a\u061Cb", "a\u061Cb"},
		{"zero-width space", "a\u200Bb", "ab"},
		{"word joiner and invisible times", "a\u2060b\u2062c", "abc"},
		{"byte order mark", "\uFEFFab", "ab"},
		{"deprecated format", "a\u206Ab\u206Fc", "abc"},
		{"tag characters", "a\U000E0001\U000E0041b", "ab"},
		{"soft hyphen", "a\u00ADb", "ab"},
		{"crlf", "a\r\nb", "a\nb"},
		{"cr", "a\rb", "a\nb"},
		{"line separator", "a\u2028b\u2029c", "a\nb\nc"},
		{"tab", "a\tb", "a    b"},
		{"invalid utf-8", "a\xffb", "ab"},
		{"truncated rune", "a\xe2\x1b[31mb", "a\uFFFD[31mb"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			got := sanitizeText(tt.input)
			a.Equal(tt.want, got)
			a.True(utf8.ValidString(got))
		})
	}
}

func TestSanitizeLine(t *testing.T) {
	a := require.New(t)
	a.Equal("a b c", sanitizeLine("a\nb\r\nc"))
}

// requireNoTerminalControls fails when s holds anything that a terminal
// treats as a control, other than line breaks.
func requireNoTerminalControls(a *require.Assertions, s string) {
	for _, r := range s {
		if r == '\n' {
			continue
		}
		a.False(
			r < 0x20 || (r >= 0x7f && r <= 0x9f) || isHiddenFormat(r),
			"control %U in %q", r, s,
		)
	}
}

// requireIndented fails when a line of rendered after the first starts in
// the first column.
func requireIndented(a *require.Assertions, rendered string) {
	lines := strings.Split(rendered, "\n")
	for _, ln := range lines[1:] {
		a.True(strings.HasPrefix(ln, " "), "line %q is not indented", ln)
	}
}

func TestRenderLines_MessageStaysUnderItsPrefix(t *testing.T) {
	at := time.Date(2026, 10, 3, 22, 0, 0, 0, time.UTC)
	long := strings.Repeat("word ", 30) + "[2026-10-03 10:00:00] You: I agree"
	tests := []struct {
		name  string
		text  string
		width int
	}{
		{"line break, no wrapping", hostile, 0},
		{"line break, wide", hostile, 80},
		{"wrapping", long, 60},
		{"narrow view", long, 30},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			s := defaultStyles()
			out := s.renderLines(
				[]chatLine{messageLine(storage.SenderPeer, at, tt.text)},
				tt.width,
			)
			a.True(strings.HasPrefix(out, "[2026-10-03 22:00:00] Peer: "))
			requireNoTerminalControls(a, out)
			requireIndented(a, out)
			if tt.width > 0 {
				for _, ln := range strings.Split(out, "\n") {
					a.LessOrEqual(len([]rune(ln)), tt.width, "line %q", ln)
				}
			}
		})
	}
}

func TestRenderLines_NoticeStaysOnOneLine(t *testing.T) {
	const forged = "[2026-10-03 10:00:00] You: I agree"
	warn, ok := checkMinorMismatch("0.7.0", "0.8.\n"+forged+
		strings.Repeat("\n"+forged, 20))
	if !ok {
		t.Fatal("no version warning")
	}
	tests := []struct {
		name string
		text string
	}{
		{"version warning", "⚠ " + warn},
		{
			"error text",
			"Error: bad frame " + strings.Repeat("x ", 30) + "\n" + forged +
				"\r\n\x1b[38;2;74;144;226m" + forged,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			s := defaultStyles()
			// Whatever the width, a wrapped line of the notice must not
			// start in the first column, where it could pass for a message.
			for _, width := range append([]int{0}, widthsFrom(8, 120)...) {
				out := s.renderLines(
					[]chatLine{noticeLine(s.highlight, tt.text)}, width,
				)
				requireNoTerminalControls(a, out)
				requireIndented(a, out)
				if width == 0 {
					a.NotContains(out, "\n")
					continue
				}
				for _, ln := range strings.Split(out, "\n") {
					a.LessOrEqual(lipgloss.Width(ln), width, "line %q", ln)
				}
			}
		})
	}
}

// widthsFrom returns the widths from lo to hi.
func widthsFrom(lo, hi int) []int {
	ws := make([]int, 0, hi-lo+1)
	for w := lo; w <= hi; w++ {
		ws = append(ws, w)
	}
	return ws
}

func TestUpdate_ChatMessageIsSanitized(t *testing.T) {
	a := require.New(t)
	m := newTestModel()
	m.state = stateChat
	m.sess = &chatSession{}

	m.Update(sessionMsg{m.sess, chatMessageMsg{
		sender: storage.SenderPeer,
		text:   hostile,
		time:   time.Date(2026, 10, 3, 22, 0, 0, 0, time.UTC),
	}})
	view := m.vp.View()
	requireNoTerminalControls(a, view)
	a.Contains(view, "Peer: hiclick")
	a.NotContains(view, "\n[2026-10-03 10:00:00] You:")
}

func TestReceiveErrorIsSanitized(t *testing.T) {
	a := require.New(t)
	m := newTestModel()
	m.state = stateChat
	m.sess = &chatSession{}

	m.Update(sessionMsg{
		m.sess, receiveErrorMsg{err: errString("bad \x1b]0;pwned\x07 frame")},
	})
	requireNoTerminalControls(a, m.vp.View())
	a.Contains(m.vp.View(), "Error: bad  frame")
}

type errString string

func (e errString) Error() string { return string(e) }

func TestHistoryIsSanitized(t *testing.T) {
	a := require.New(t)
	store, err := storage.OpenStorage(
		storage.WithDBPath(filepath.Join(t.TempDir(), "db")),
		storage.WithNoPassphrase(),
	)
	a.NoError(err)
	t.Cleanup(func() { _ = store.Close() })
	const sid = "SESSION"
	a.NoError(store.AddChatEntry(
		sid, []byte(hostile), time.Now(), storage.SenderPeer,
	))

	m := newTestModel()
	m.store = store
	m.width, m.height = 80, 24
	m.state = stateHistory

	msg := loadSessionMessages(store, sid)()
	m.Update(msg)
	a.True(m.histViewing)
	view := m.histVP.View()
	requireNoTerminalControls(a, view)
	a.Contains(view, "Peer: hiclick")
	requireIndented(a, strings.TrimRight(view, " \n"))
}
