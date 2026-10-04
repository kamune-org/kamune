package main

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
)

func TestDisplayVersion(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"plain", "0.7.0", "0.7.0"},
		{"empty", "", ""},
		{
			"line break and escape",
			"0.8.0\n\x1b]0;pwned\x07x",
			"0.8.0 x",
		},
		{
			"too long",
			"0.8." + strings.Repeat("1", 40),
			"0.8." + strings.Repeat("1", maxVersionLength-4) + "…",
		},
		{
			"too long, multi-byte",
			"0.8." + strings.Repeat("é", 20),
			"0.8." + strings.Repeat("é", (maxVersionLength-4)/2) + "…",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			got := displayVersion(tt.input)
			a.Equal(tt.want, got)
			a.True(utf8.ValidString(got))
			a.NotContains(got, "\n")
		})
	}
}

func TestCheckMinorMismatch(t *testing.T) {
	tests := []struct {
		name     string
		local    string
		remote   string
		mismatch bool
		contains string
	}{
		{"same", "1.7.0", "1.7.3", false, ""},
		{"other major", "1.7.0", "2.8.0", false, ""},
		{"other minor", "1.7.0", "1.8.0", true, "v1.7.0 vs v1.8.0"},
		// The handshake rejects these peers, so no chat has them.
		{"other minor before 1.0", "0.7.0", "0.8.0", false, ""},
		{"other major before 1.0", "0.7.0", "1.7.0", false, ""},
		{"empty", "1.7.0", "", false, ""},
		{"not a version", "1.7.0", "x.y", false, ""},
		{
			"hostile patch",
			"1.7.0",
			"1.8.\n[2026-10-03 10:00:00] You: I agree" +
				strings.Repeat(" padding", 20),
			true,
			"v1.7.0 vs v1.8. [2026-10-03 10:00:00] You: …",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			warn, mismatch := checkMinorMismatch(tt.local, tt.remote)
			a.Equal(tt.mismatch, mismatch)
			if !tt.mismatch {
				a.Empty(warn)
				return
			}
			a.Contains(warn, tt.contains)
			a.NotContains(warn, "\n")
		})
	}
}
