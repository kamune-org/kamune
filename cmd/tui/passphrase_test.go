package main

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

// scripted returns a prompter that reads secrets and lines from the given
// answers, in order, and writes its prompts to out.
func scripted(out *bytes.Buffer, secrets, lines []string) prompter {
	return prompter{
		out: out,
		readSecret: func() ([]byte, error) {
			if len(secrets) == 0 {
				return nil, io.EOF
			}
			s := secrets[0]
			secrets = secrets[1:]
			return []byte(s), nil
		},
		readLine: func() (string, error) {
			if len(lines) == 0 {
				return "", io.EOF
			}
			l := lines[0]
			lines = lines[1:]
			return l, nil
		},
	}
}

func TestPrompterPassphrase(t *testing.T) {
	tests := []struct {
		name     string
		isNew    bool
		secrets  []string
		lines    []string
		want     string
		wantErr  error
		eof      bool
		mismatch bool
	}{
		{name: "existing", secrets: []string{"secret"}, want: "secret"},
		{
			name: "new, repeated", isNew: true,
			secrets: []string{"secret", "secret"}, want: "secret",
		},
		{
			name: "new, typo then repeated", isNew: true,
			secrets:  []string{"secret", "secrte", "secret", "secret"},
			want:     "secret",
			mismatch: true,
		},
		{
			name: "new, never repeated", isNew: true,
			secrets:  []string{"a", "b", "c", "d", "e", "f"},
			wantErr:  errNoPassphrase,
			mismatch: true,
		},
		{
			name: "empty, confirmed", secrets: []string{""},
			lines: []string{"y"}, want: "",
		},
		{
			name: "empty, confirmed with yes", isNew: true,
			secrets: []string{""}, lines: []string{" YES "}, want: "",
		},
		{
			name: "empty, declined then given", secrets: []string{"", "pw"},
			lines: []string{"n"}, want: "pw",
		},
		{
			name: "empty, default is no", secrets: []string{"", "", ""},
			lines: []string{"", "", ""}, wantErr: errNoPassphrase,
		},
		{name: "no input", eof: true},
		{
			name: "no answer", secrets: []string{""}, eof: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			var out bytes.Buffer
			got, err := scripted(&out, tt.secrets, tt.lines).
				passphrase(tt.isNew)
			switch {
			case tt.eof:
				a.ErrorIs(err, io.EOF)
				return
			case tt.wantErr != nil:
				a.True(errors.Is(err, tt.wantErr), "error %v", err)
			default:
				a.NoError(err)
				a.Equal(tt.want, string(got))
			}
			if tt.mismatch {
				a.Contains(out.String(), "do not match")
			}
			switch {
			case !tt.isNew:
				a.NotContains(out.String(), "Repeat passphrase")
			case tt.want != "" || tt.mismatch:
				a.Contains(out.String(), "Repeat passphrase")
			}
			if len(tt.secrets) > 0 && tt.secrets[0] == "" {
				a.Contains(out.String(), "without a passphrase?")
			}
		})
	}
}
