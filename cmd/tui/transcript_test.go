package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune"
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
	warn, ok := checkMinorMismatch("1.7.0", "1.8.\n"+forged+
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

func TestClipMessage(t *testing.T) {
	long := strings.Repeat("é", maxShownRunes+10)
	tall := strings.Repeat("x\n", maxShownLines+5)
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"short", "hello", "hello"},
		{"at the rune limit", long[:2*maxShownRunes], long[:2*maxShownRunes]},
		{
			"over the rune limit", long,
			long[:2*maxShownRunes] + " … (10 more characters not shown)",
		},
		{
			"over the line limit", tall,
			strings.Repeat("x\n", maxShownLines-1) + "x" +
				" … (11 more characters not shown)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			a.Equal(tt.want, clipMessage(tt.input))
		})
	}
}

// chatModel returns a model in a chat with no connection behind it, for
// tests of the transcript.
func chatModel() *model {
	m := newTestModel()
	m.state = stateChat
	m.sess = &chatSession{}
	return m
}

// requireLaidOut checks that the transcript laid out piece by piece is
// what laying it all out at once gives.
func requireLaidOut(a *require.Assertions, m *model) {
	a.Equal(
		m.s.renderLines(m.messages, contentWidth(m.vp)),
		strings.Join(m.rendered, "\n"),
	)
}

func TestTranscript_IsBounded(t *testing.T) {
	a := require.New(t)
	m := chatModel()
	at := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	for i := range 2*maxTranscriptLines + 5 {
		m.Update(sessionMsg{m.sess, chatMessageMsg{
			sender: storage.SenderPeer,
			text:   fmt.Sprint("message ", i),
			time:   at,
		}})
	}
	a.Len(m.messages, maxTranscriptLines)
	a.False(m.messages[0].message)
	a.Contains(m.messages[0].text, "View Chat History")
	a.Equal(
		fmt.Sprint("message ", 2*maxTranscriptLines+4),
		m.messages[len(m.messages)-1].text,
	)
	requireLaidOut(a, m)

	// A message near the frame size is cut short on screen.
	m.Update(sessionMsg{m.sess, chatMessageMsg{
		sender: storage.SenderPeer,
		text:   strings.Repeat("a", 60*1024),
		time:   at,
	}})
	last := m.messages[len(m.messages)-1].text
	a.Less(utf8.RuneCountInString(last), maxShownRunes+50)
	a.Contains(last, "more characters not shown")
	requireLaidOut(a, m)
}

func TestTranscript_LaidOutAfterEveryChange(t *testing.T) {
	a := require.New(t)
	m := chatModel()
	at := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	add := func(text string) {
		m.Update(sessionMsg{m.sess, chatMessageMsg{
			sender: storage.SenderPeer, text: text, time: at,
		}})
	}

	add("first")
	requireLaidOut(a, m)
	m.Update(sessionMsg{m.sess, historyLoadedMsg{messages: []chatLine{
		noticeLine(m.s.muted, "Session ID is X."),
		messageLine(storage.SenderLocal, at, "from history"),
	}}})
	a.Len(m.messages, 3)
	requireLaidOut(a, m)
	add(strings.Repeat("word ", 40))
	requireLaidOut(a, m)
	m.Update(tea.WindowSizeMsg{Width: 40, Height: 20})
	requireLaidOut(a, m)
	add("after resize")
	requireLaidOut(a, m)
	a.Contains(m.vp.View(), "after resize")
}

func TestReceive_SavesBeforeUpdate(t *testing.T) {
	a := require.New(t)
	msgs := make(chan tea.Msg, 16)
	m := chatSending(t, modeDirectDial, func(t *kamune.Transport) error {
		_, err := t.Send(
			kamune.Bytes([]byte("hi")), kamune.RouteExchangeMessages,
		)
		return err
	}, func(msg tea.Msg) { msgs <- msg })

	for {
		sm, ok := waitFor(t, msgs).(sessionMsg)
		if !ok {
			continue
		}
		if c, ok := sm.msg.(chatMessageMsg); ok {
			a.Equal("hi", c.text)
			a.NoError(c.saveErr)
			break
		}
	}
	// Update has not seen the message, yet it is in the history.
	history, err := m.store.GetChatHistory(m.sess.t.SessionID())
	a.NoError(err)
	a.Len(history, 1)
	a.Equal("hi", string(history[0].Data))
	a.Empty(m.messages)
}
