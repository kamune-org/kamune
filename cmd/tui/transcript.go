package main

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/charmbracelet/bubbles/viewport"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/kamune-org/kamune/pkg/storage"
)

// minMessageWidth is the narrowest column that a message is wrapped into
// beside its prefix. In a narrower view, the message goes below the prefix.
const minMessageWidth = 16

// maxTranscriptLines bounds how many entries the chat view keeps. Older
// ones leave the view, not the history.
const maxTranscriptLines = 500

// maxShownRunes and maxShownLines bound how much of one message a
// transcript shows. A peer can send close to 64 KiB in one message; what
// is beyond these limits is left out of the view, not of the history.
const (
	maxShownRunes = 2000
	maxShownLines = 40
)

// chatLine is one entry of a transcript: a chat message, or a notice from
// the TUI itself. Entries are kept unrendered, so that they can be laid out
// again when the window size changes.
type chatLine struct {
	time  time.Time
	text  string
	style lipgloss.Style
	// sender is who sent a message; it is unused for a notice.
	sender storage.Sender
	// message tells a chat message from a notice.
	message bool
}

// messageLine returns a chat message for a transcript. text is sanitized
// (see sanitizeText), since it comes from a peer or the database, and
// clipped (see clipMessage).
func messageLine(sender storage.Sender, at time.Time, text string) chatLine {
	return chatLine{
		time:    at,
		text:    clipMessage(sanitizeText(text)),
		sender:  sender,
		message: true,
	}
}

// noticeLine returns a notice for a transcript, shown in style. A notice
// is one line of the TUI's own text, which may quote what a peer sent, in
// error messages or the version warning. So text is sanitized and its line
// breaks become spaces (see sanitizeLine).
func noticeLine(style lipgloss.Style, text string) chatLine {
	return chatLine{style: style, text: sanitizeLine(text)}
}

// clipMessage cuts text to at most maxShownRunes runes on maxShownLines
// lines, and says how much it left out.
func clipMessage(text string) string {
	runes, lines := 0, 1
	for i, r := range text {
		if runes == maxShownRunes || (r == '\n' && lines == maxShownLines) {
			return text[:i] + fmt.Sprintf(
				" … (%d more characters not shown)",
				utf8.RuneCountInString(text[i:]),
			)
		}
		runes++
		if r == '\n' {
			lines++
		}
	}
	return text
}

// notSavedLine returns the notice shown when a message could not be added
// to chat history.
func notSavedLine(s styles, err error) chatLine {
	return noticeLine(
		s.err, "The message above was not saved to history: "+err.Error(),
	)
}

// noticeIndent is how far the lines of a wrapped notice after its first
// are indented.
const noticeIndent = 2

// renderLines lays out a transcript for a view that is width cells wide;
// a width of 0 or less turns wrapping off.
//
// A message is shown after a "[time] You: " or "[time] Peer: " prefix, and
// every further line of it, from a line break in the text or from
// wrapping, is indented by the width of that prefix. A notice starts with
// the TUI's own words and every line it wraps onto is indented by
// noticeIndent. Only the TUI writes in the first column, so neither can
// pass off part of its text as a message.
func (s styles) renderLines(lines []chatLine, width int) string {
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		out = append(out, s.renderLine(l, width))
	}
	return strings.Join(out, "\n")
}

// renderLine lays out one entry of a transcript; see renderLines.
func (s styles) renderLine(l chatLine, width int) string {
	if !l.message {
		return renderNotice(l, width)
	}
	return s.renderMessage(l, width)
}

func renderNotice(l chatLine, width int) string {
	text := l.text
	if width > 0 {
		text = ansi.Wrap(text, max(width-noticeIndent, 1), "")
	}
	pad := strings.Repeat(" ", noticeIndent)
	lines := strings.Split(text, "\n")
	for i, ln := range lines {
		lines[i] = l.style.Render(ln)
		if i > 0 {
			lines[i] = pad + lines[i]
		}
	}
	return strings.Join(lines, "\n")
}

func (s styles) renderMessage(l chatLine, width int) string {
	who, ps, ts := "You", s.userPrefix, s.userText
	if l.sender != storage.SenderLocal {
		who, ps, ts = "Peer", s.peerPrefix, s.peerText
	}
	prefix := "[" + l.time.Format(time.DateTime) + "] " + who + ": "
	indent := lipgloss.Width(prefix)
	below := width > 0 && width-indent < minMessageWidth
	if below {
		indent = 2
	}
	text := l.text
	if width > 0 {
		text = ansi.Wrap(text, max(width-indent, 1), "")
	}
	pad := strings.Repeat(" ", indent)

	var b strings.Builder
	b.WriteString(ps.Render(prefix))
	for i, ln := range strings.Split(text, "\n") {
		if i > 0 || below {
			b.WriteString("\n" + pad)
		}
		b.WriteString(ts.Render(ln))
	}
	return b.String()
}

// contentWidth returns the width inside the frame of vp.
func contentWidth(vp viewport.Model) int {
	return vp.Width - vp.Style.GetHorizontalFrameSize()
}
