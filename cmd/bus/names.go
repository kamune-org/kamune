package main

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/kamune-org/kamune"
)

// maxLocalNameLength caps the local name, in bytes. It is lower than
// kamune.MaxPeerNameLength, the most the protocol accepts.
const maxLocalNameLength = 32

// errNameRequired rejects an empty name where one is needed.
var errNameRequired = errors.New("name is required")

// validateLabel trims a name the user typed for a peer or a session and
// checks it with kamune.ValidatePeerName, the rule peers' introductions
// must pass: at most kamune.MaxPeerNameLength bytes of valid UTF-8, with
// no control, line-separator or format characters such as bidirectional
// overrides. A name that reads as nothing, such as one made only of
// U+3164 HANGUL FILLER, is no name; see nameSkeleton.
func validateLabel(name string) (string, error) {
	name = strings.TrimSpace(name)
	if nameSkeleton(name) == "" {
		return "", errNameRequired
	}
	if err := kamune.ValidatePeerName(name); err != nil {
		return "", err
	}
	return name, nil
}

// nameRuneAllowed reports whether escapeLogText writes r as it is: r is
// not a control, line-separator or format character, except the two
// zero-width joiners, which names in some scripts and emoji need.
func nameRuneAllowed(r rune) bool {
	switch {
	case r == '\u200C', r == '\u200D':
		return true
	case unicode.IsControl(r):
		return false
	default:
		return !unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp)
	}
}

// sanitizeName makes a name safe to show, for names stored before the
// protocol limited them. It is kamune.SanitizePeerName: every code point
// kamune.ValidatePeerName rejects, and every invalid UTF-8 sequence,
// becomes U+FFFD, and a name longer than kamune.MaxPeerNameLength bytes
// is cut on a rune boundary and ends with an ellipsis. The result always
// passes kamune.ValidatePeerName.
func sanitizeName(name string) string {
	return kamune.SanitizePeerName(name)
}

// escapeLogText keeps a log message on one line and shown as written:
// line breaks, tabs and other control, line-separator and format
// characters, such as bidirectional overrides, are written as escapes,
// so text a peer chose cannot forge log lines or reorder them.
func escapeLogText(s string) string {
	clean := true
	for _, r := range s {
		if r == utf8.RuneError || !nameRuneAllowed(r) {
			clean = false
			break
		}
	}
	if clean {
		return s
	}

	var b strings.Builder
	for i, r := range s {
		switch {
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == utf8.RuneError:
			if _, size := utf8.DecodeRuneInString(s[i:]); size == 1 {
				fmt.Fprintf(&b, `\x%02x`, s[i])
			} else {
				b.WriteRune(r)
			}
		case !nameRuneAllowed(r):
			fmt.Fprintf(&b, `\u%04X`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
