package main

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/charmbracelet/x/ansi"

	"github.com/kamune-org/kamune"
)

// sanitizeText makes text that a peer sent, or that was read from the
// database, safe to print on the terminal. It removes terminal escape
// sequences (CSI, OSC, DCS and the rest) whole, and then drops every
// control character that is left (C0, DEL and C1, which include the
// escape character) and the invisible format characters that
// [isHiddenFormat] reports. Tabs become spaces, and CR, CRLF and the
// Unicode line and paragraph separators become "\n", so that the caller
// decides how a line break is shown. The result is valid UTF-8.
func sanitizeText(s string) string {
	s = ansi.Strip(s)
	s = strings.ReplaceAll(s, "\r\n", "\n")
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n', r == '\r', r == '\u2028', r == '\u2029':
			b.WriteByte('\n')
		case r == '\t':
			b.WriteString("    ")
		case unicode.IsControl(r), isHiddenFormat(r):
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// sanitizeLine is [sanitizeText] for text shown on a single line: line
// breaks become spaces.
func sanitizeLine(s string) string {
	return strings.ReplaceAll(sanitizeText(s), "\n", " ")
}

// isHiddenFormat reports whether r is an invisible format character
// (Unicode category Cf) that sanitizeText drops. Among them are the
// bidirectional embeddings, overrides and isolates (U+202A to U+202E and
// U+2066 to U+2069), which reorder the text after them, and characters
// such as the zero-width space, the word joiner, the byte order mark and
// the tag characters, which hide or split text without showing. As in
// [kamune.ValidatePeerName], ZWNJ and ZWJ are kept, since Persian text and
// emoji sequences need them. So are the marks LRM, RLM and ALM, which only
// act as a strong character. Flags built from tag characters lose their
// region and show as a plain black flag.
func isHiddenFormat(r rune) bool {
	switch r {
	case '\u200C', '\u200D', '\u200E', '\u200F', '\u061C':
		return false
	}
	return unicode.Is(unicode.Cf, r)
}

// displayName returns a peer's name for display on one line, or
// "(unnamed)" for an empty name. A name that a peer introduces itself with
// has passed [kamune.ValidatePeerName], but a peer stored by an older
// version may have any name. Such a name is shown without the code points
// that the check rejects and cut to [kamune.MaxPeerNameLength] bytes.
func displayName(name string) string {
	if kamune.ValidatePeerName(name) != nil {
		var b strings.Builder
		for _, r := range sanitizeLine(name) {
			if b.Len()+utf8.RuneLen(r) > kamune.MaxPeerNameLength {
				break
			}
			if kamune.ValidatePeerName(string(r)) == nil {
				b.WriteRune(r)
			}
		}
		name = b.String()
	}
	if name == "" {
		return "(unnamed)"
	}
	return name
}
