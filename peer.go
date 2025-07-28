package kamune

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/hossein1376/kamune/pkg/attest"
)

var baseDir, privKeyPath string

const (
	keyName        = "id.key"
	knownPeersName = "known"
)

type Peer struct {
	transport   *Transport
	pubKey      PublicKey
	greetedAt   time.Time
	lastSeenAt  time.Time
	hasPeerLeft bool
}

func init() {
	home, err := os.UserHomeDir()
	if err != nil {
		panic(fmt.Errorf("getting home dir: %w", err))
	}
	baseDir = filepath.Join(home, ".config", "kamune")
	privKeyPath = filepath.Join(baseDir, keyName)

	_, err = os.Stat(privKeyPath)
	switch {
	case err == nil:
		return
	case errors.Is(err, os.ErrNotExist):
		if err := newCert(); err != nil {
			panic(fmt.Errorf("creating certificate: %w", err))
		}
	default:
		panic(fmt.Errorf("checking private key's existence: %w", err))
	}
}

func isPeerKnown(claim []byte) bool {
	peers, err := os.ReadFile(filepath.Join(baseDir, knownPeersName))
	if err != nil {
		return false
	}
	for _, peer := range bytes.Split(peers, []byte("\n")) {
		if bytes.Compare(peer, claim) == 0 {
			return true
		}
	}

	return false
}

func trustPeer(peer []byte) error {
	f, err := os.OpenFile(
		filepath.Join(baseDir, knownPeersName),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		0600,
	)
	if err != nil {
		return fmt.Errorf("opening file: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(append(peer, '\n')); err != nil {
		return fmt.Errorf("writing to file: %w", err)
	}

	return nil
}

func newCert() error {
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return fmt.Errorf("MkdirAll: %w", err)
	}
	id, err := attest.New()
	if err != nil {
		return fmt.Errorf("new attest: %w", err)
	}
	if err := id.Save(privKeyPath); err != nil {
		return fmt.Errorf("saving cert: %w", err)
	}

	return nil
}
