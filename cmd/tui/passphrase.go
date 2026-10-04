package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/kamune-org/kamune/pkg/storage"
)

// maxPassphraseAttempts is how many times the user is asked for a
// passphrase before the TUI gives up.
const maxPassphraseAttempts = 3

// errNoPassphrase is returned by [prompter.passphrase] and [openDB] when
// the user settled on no passphrase within maxPassphraseAttempts tries.
var errNoPassphrase = errors.New("no passphrase chosen")

// prompter asks the user questions on the terminal before the UI starts.
type prompter struct {
	out io.Writer
	// readLine reads one line of visible input, without the line break.
	readLine func() (string, error)
	// readSecret reads one line of input without echoing it.
	readSecret func() ([]byte, error)
}

// passphrase asks for a database passphrase, with label as the prompt,
// up to maxPassphraseAttempts times (see askPassphrase).
func (p prompter) passphrase(label string, isNew bool) ([]byte, error) {
	for range maxPassphraseAttempts {
		pass, ok, err := p.askPassphrase(label, isNew)
		if err != nil || ok {
			return pass, err
		}
	}
	return nil, errNoPassphrase
}

// askPassphrase asks once for a database passphrase, with label as the
// prompt. When the passphrase is a new one (isNew), for a database that
// does not exist yet or for a change, it asks twice, since a typo would
// lock the user out of the database. An empty passphrase is the same as
// storage.WithNoPassphrase: anyone who can copy the database file can read
// it. It is accepted only after the user confirms that. ok is false when
// the user settled on no passphrase: an empty one was not confirmed or the
// two did not match.
func (p prompter) askPassphrase(
	label string, isNew bool,
) (pass []byte, ok bool, err error) {
	pass, err = p.secret(label + ": ")
	if err != nil {
		return nil, false, err
	}
	if len(pass) == 0 {
		ok, err := p.confirmEmpty()
		if err != nil || !ok {
			return nil, false, err
		}
		return pass, true, nil
	}
	if !isNew {
		return pass, true, nil
	}
	again, err := p.secret("Repeat " + strings.ToLower(label) + ": ")
	if err != nil {
		return nil, false, err
	}
	if !bytes.Equal(pass, again) {
		fmt.Fprintln(p.out, "The passphrases do not match.")
		return nil, false, nil
	}
	return pass, true, nil
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

// openDB opens the database at path with envPass, or, when envPass is
// empty, with a passphrase it asks p for, and returns the passphrase that
// opened it. It asks at most maxPassphraseAttempts times in all, counting
// each passphrase that does not open the database, after which it says so,
// and each try that askPassphrase gives up on. It then returns an error
// wrapping storage.ErrWrongPassphrase when the last passphrase was wrong,
// or errNoPassphrase.
func openDB(
	path string, envPass []byte, p prompter,
) (*storage.Storage, []byte, error) {
	open := func(pass []byte) (*storage.Storage, error) {
		return storage.OpenStorage(
			storage.WithDBPath(path),
			storage.WithPassphraseHandler(func() ([]byte, error) {
				return pass, nil
			}),
		)
	}
	if len(envPass) > 0 {
		store, err := open(envPass)
		return store, envPass, err
	}

	_, statErr := os.Stat(path)
	isNew := errors.Is(statErr, fs.ErrNotExist)
	err := errNoPassphrase
	for range maxPassphraseAttempts {
		pass, ok, perr := p.askPassphrase("Passphrase", isNew)
		if perr != nil {
			return nil, nil, perr
		}
		if !ok {
			err = errNoPassphrase
			continue
		}
		store, oerr := open(pass)
		if !errors.Is(oerr, storage.ErrWrongPassphrase) {
			return store, pass, oerr
		}
		fmt.Fprintln(p.out, "Wrong passphrase.")
		err = oerr
	}
	return nil, nil, err
}

// changePassphrase asks p for a new passphrase, twice, and puts it in place
// of oldPass, the passphrase that opened store. An empty passphrase needs
// the same confirmation as at startup. An error wrapping storage.ErrReopen
// means that the new passphrase is in effect, but store must be closed and
// the database opened again.
func changePassphrase(
	store *storage.Storage, oldPass []byte, p prompter,
) error {
	newPass, err := p.passphrase("New passphrase", true)
	if err != nil {
		return err
	}
	if err := store.ChangePassphrase(oldPass, newPass); err != nil {
		return err
	}
	fmt.Fprintln(p.out, "Passphrase changed.")
	return nil
}
