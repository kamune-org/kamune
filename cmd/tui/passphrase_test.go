package main

import (
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/pkg/storage"
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

func TestOpenDB_AsksAgainAfterAWrongPassphrase(t *testing.T) {
	a := require.New(t)
	path := filepath.Join(t.TempDir(), "db")

	var out bytes.Buffer
	store, err := openDB(path, nil, scripted(&out, []string{"pw", "pw"}, nil))
	a.NoError(err)
	a.Contains(out.String(), "Repeat passphrase")
	a.NoError(store.Close())

	out.Reset()
	store, err = openDB(path, nil, scripted(
		&out, []string{"wrong", "pw"}, nil,
	))
	a.NoError(err)
	a.NoError(store.Close())
	a.Equal(1, strings.Count(out.String(), "Wrong passphrase."))
	a.NotContains(out.String(), "Repeat passphrase")

	out.Reset()
	_, err = openDB(path, nil, scripted(
		&out, []string{"a", "b", "c", "pw"}, nil,
	))
	a.ErrorIs(err, storage.ErrWrongPassphrase)
	a.Equal(
		maxPassphraseAttempts, strings.Count(out.String(), "Wrong passphrase."),
	)

	_, err = openDB(path, []byte("wrong"), scripted(&out, nil, nil))
	a.ErrorIs(err, storage.ErrWrongPassphrase)
	store, err = openDB(path, []byte("pw"), scripted(&out, nil, nil))
	a.NoError(err)
	a.NoError(store.Close())
}

func TestOpenDB_LimitsTriesInAll(t *testing.T) {
	a := require.New(t)
	dir := t.TempDir()
	existing := filepath.Join(dir, "db")
	store, err := openDB(
		existing, nil, scripted(&bytes.Buffer{}, []string{"pw", "pw"}, nil),
	)
	a.NoError(err)
	a.NoError(store.Close())

	tests := []struct {
		name    string
		path    string
		secrets []string
		lines   []string
		wantErr error
		wrong   int
	}{
		{
			name: "declined empty, then wrong", path: existing,
			secrets: []string{"", "a", "b", "pw"}, lines: []string{"n"},
			wantErr: storage.ErrWrongPassphrase, wrong: 2,
		},
		{
			name: "wrong, then declined empty", path: existing,
			secrets: []string{"a", "", "", "pw"},
			lines:   []string{"n", "n", "y"},
			wantErr: errNoPassphrase, wrong: 1,
		},
		{
			name: "new, never repeated", path: filepath.Join(dir, "new"),
			secrets: []string{"a", "b", "c", "d", "e", "f", "pw", "pw"},
			wantErr: errNoPassphrase,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			var out bytes.Buffer
			_, err := openDB(tt.path, nil, scripted(&out, tt.secrets, tt.lines))
			a.ErrorIs(err, tt.wantErr)
			a.Equal(
				maxPassphraseAttempts, strings.Count(out.String(), "Passphrase: "),
			)
			a.Equal(tt.wrong, strings.Count(out.String(), "Wrong passphrase."))
			a.NoFileExists(filepath.Join(dir, "new"))
		})
	}
}
