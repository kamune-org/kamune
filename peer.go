package kamune

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hossein1376/kamune/pkg/attest"
)

const (
	knownPeersFilename = "known"
)

var keyPathDir string

func init() {
	keyPath, ok := os.LookupEnv("KAMUNE_KEY_PATH")
	if !ok {
		home, err := os.UserHomeDir()
		if err != nil {
			panic(fmt.Errorf("getting home dir: %w", err))
		}
		keyPath = filepath.Join(home, ".config", "kamune")
	}
	keyPathDir = keyPath

	err := checkExistence(filepath.Join(keyPath, attest.Ed25519.String()))
	if err != nil {
		panic(fmt.Errorf("ed25519 key: %w", err))
	}
	err = checkExistence(filepath.Join(keyPath, attest.MLDSA.String()))
	if err != nil {
		panic(fmt.Errorf("mldsa key: %w", err))
	}
}

func checkExistence(path string) error {
	_, err := os.Stat(path)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, os.ErrNotExist):
		if err := newCert(); err != nil {
			return fmt.Errorf("creating cert in %s: %w", path, err)
		}
	default:
		return fmt.Errorf("checking key's existence: %w", err)
	}
	return nil
}

func isPeerKnown(claim string) bool {
	peers, err := os.ReadFile(filepath.Join(keyPathDir, knownPeersFilename))
	if err != nil {
		return false
	}
	for _, peer := range bytes.Split(peers, []byte("\n")) {
		if bytes.Compare(peer, []byte(claim)) == 0 {
			return true
		}
	}

	return false
}

func trustPeer(peer string) error {
	f, err := os.OpenFile(
		filepath.Join(keyPathDir, knownPeersFilename),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		0600,
	)
	if err != nil {
		return fmt.Errorf("opening file: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(append([]byte(peer), '\n')); err != nil {
		return fmt.Errorf("writing to file: %w", err)
	}

	return nil
}

func newCert() error {
	if err := os.MkdirAll(keyPathDir, 0700); err != nil {
		return fmt.Errorf("MkdirAll: %w", err)
	}

	ed, err := attest.Ed25519.New()
	if err != nil {
		return fmt.Errorf("new ed25519: %w", err)
	}
	err = ed.Save(filepath.Join(keyPathDir, attest.Ed25519.String()))
	if err != nil {
		return fmt.Errorf("saving ed25519: %w", err)
	}

	ml, err := attest.MLDSA.New()
	if err != nil {
		return fmt.Errorf("new mldsa: %w", err)
	}
	err = ml.Save(filepath.Join(keyPathDir, attest.MLDSA.String()))
	if err != nil {
		return fmt.Errorf("saving mldsa: %w", err)
	}

	return nil
}
