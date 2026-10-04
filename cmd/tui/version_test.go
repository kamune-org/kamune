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
		remote   string
		mismatch bool
		contains string
	}{
		{"same", "0.7.3", false, ""},
		{"other major", "1.8.0", false, ""},
		{"other minor", "0.8.0", true, "v0.7.0 vs v0.8.0"},
		{"empty", "", false, ""},
		{"not a version", "x.y", false, ""},
		{
			"hostile patch",
			"0.8.\n[2026-10-03 10:00:00] You: I agree" +
				strings.Repeat(" padding", 20),
			true,
			"v0.7.0 vs v0.8. [2026-10-03 10:00:00] You: …",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			warn, mismatch := checkMinorMismatch("0.7.0", tt.remote)
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
