package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
)

// maxPassphraseAttempts is how many times the user is asked for a
// passphrase before the TUI gives up.
const maxPassphraseAttempts = 3

// errNoPassphrase is returned by [prompter.passphrase] when the user gave
// no passphrase it could use within maxPassphraseAttempts tries.
var errNoPassphrase = errors.New("no passphrase chosen")

// prompter asks the user questions on the terminal before the UI starts.
type prompter struct {
	out io.Writer
	// readLine reads one line of visible input, without the line break.
	readLine func() (string, error)
	// readSecret reads one line of input without echoing it.
	readSecret func() ([]byte, error)
}

// passphrase asks for the database passphrase. When the database does not
// exist yet (isNew), it asks twice, since a typo would lock the user out
// of the identity about to be created. An empty passphrase is the same as
// storage.WithNoPassphrase: anyone who can copy the database file can read
// it. It is accepted only after the user confirms that.
func (p prompter) passphrase(isNew bool) ([]byte, error) {
	for range maxPassphraseAttempts {
		pass, err := p.secret("Passphrase: ")
		if err != nil {
			return nil, err
		}
		if len(pass) == 0 {
			ok, err := p.confirmEmpty()
			if err != nil {
				return nil, err
			}
			if ok {
				return pass, nil
			}
			continue
		}
		if !isNew {
			return pass, nil
		}
		again, err := p.secret("Repeat passphrase: ")
		if err != nil {
			return nil, err
		}
		if bytes.Equal(pass, again) {
			return pass, nil
		}
		fmt.Fprintln(p.out, "The passphrases do not match.")
	}
	return nil, errNoPassphrase
}

func (p prompter) secret(prompt string) ([]byte, error) {
	fmt.Fprint(p.out, prompt)
	b, err := p.readSecret()
	fmt.Fprintln(p.out)
	if err != nil {
		return nil, fmt.Errorf("reading passphrase: %w", err)
	}
	return b, nil
}

// confirmEmpty asks whether to go on without a passphrase. Only "y" or
// "yes" counts as a yes.
func (p prompter) confirmEmpty() (bool, error) {
	fmt.Fprintln(p.out, "Without a passphrase, anyone who can copy the "+
		"database file can read your identity key and chat history.")
	fmt.Fprint(p.out, "Use the database without a passphrase? [y/N]: ")
	line, err := p.readLine()
	if err != nil {
		return false, fmt.Errorf("reading answer: %w", err)
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}
