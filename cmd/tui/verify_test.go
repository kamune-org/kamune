package main

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/storage"
)

func TestDisplayName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"valid", "alice", "alice"},
		{"empty", "", "(unnamed)"},
		{"persian with zwnj", "ع\u200Cر", "ع\u200Cر"},
		{"line breaks", "bob\nalice", "bob alice"},
		{"escape sequence", "bob\x1b]0;pwned\x07", "bob"},
		{"zero-width space", "bo\u200Bb", "bob"},
		{"bidi override", "\u202Ebob", "bob"},
		{"only controls", "\x1b\x07", "(unnamed)"},
		{
			"too long",
			strings.Repeat("a", kamune.MaxPeerNameLength+10),
			strings.Repeat("a", kamune.MaxPeerNameLength),
		},
		{
			"too long, multi-byte",
			"\n" + strings.Repeat("é", kamune.MaxPeerNameLength),
			" " + strings.Repeat("é", kamune.MaxPeerNameLength/2-1),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			got := displayName(tt.input)
			a.Equal(tt.want, got)
			if got != "(unnamed)" {
				a.NoError(kamune.ValidatePeerName(got))
			}
		})
	}
}

func TestViewVerify_PeerClaimsComeAfterFingerprints(t *testing.T) {
	a := require.New(t)
	m := newTestModel()
	m.state = stateVerify
	m.verifyReq = &verifyRequest{
		peer: &storage.Peer{
			Name: "Alice\x1b]0;x\x07\n\nHex fingerprint:\n  FAKE\n\n" +
				"✓ This peer has connected before.",
			AppVersion: "0.7.0\x1b]52;c;aGk=\x07\n" +
				strings.Repeat("9", 100),
		},
		numericFP:      "11111 22222",
		localNumericFP: "33333 44444",
		emojiFP:        "E1 E2",
		hexFP:          "AA:BB",
		isNew:          true,
	}

	view := m.viewVerify()
	requireNoTerminalControls(a, view)
	var headings int
	for _, ln := range strings.Split(view, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "Hex fingerprint:") {
			headings++
		}
	}
	a.Equal(1, headings)
	numericAt := strings.Index(view, "11111 22222")
	hexAt := strings.Index(view, "AA:BB")
	claimAt := strings.Index(view, "Claimed name (unverified): Alice")
	a.Positive(numericAt)
	a.Less(numericAt, strings.Index(view, "33333 44444"))
	a.Less(numericAt, strings.Index(view, "E1 E2"))
	a.Greater(hexAt, numericAt)
	a.Greater(claimAt, hexAt)
	a.Less(strings.Index(view, "not known"), claimAt)
	for _, ln := range strings.Split(view, "\n") {
		if strings.Contains(ln, "FAKE") {
			a.Contains(ln, "Claimed name (unverified):")
		}
	}
	nines := maxVersionLength - len("0.7.0 ")
	a.Contains(view, "App version: 0.7.0 "+strings.Repeat("9", nines)+"…")
	a.NotContains(view, strings.Repeat("9", nines+1))
	a.NotContains(view, "Stored name")
}

func TestViewVerify_KnownPeerShowsStoredName(t *testing.T) {
	a := require.New(t)
	m := newTestModel()
	m.state = stateVerify
	m.verifyReq = &verifyRequest{
		peer:      &storage.Peer{Name: "Mallory"},
		knownName: "Alice",
		emojiFP:   "E1 E2",
		hexFP:     "AA:BB",
	}

	view := m.viewVerify()
	a.Contains(view, "If its app shows no numeric fingerprint, compare")
	a.Contains(view, "the hex fingerprint instead.")
	for _, ln := range strings.Split(view, "\n") {
		ln = strings.TrimRight(ln, " ")
		a.LessOrEqual(lipgloss.Width(ln), 80, "line %q", ln)
	}
	a.Contains(view, "connected before")
	a.Contains(view, "Stored name: Alice")
	a.Contains(view, "Claimed name (unverified): Mallory")
}
