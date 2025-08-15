package kamune

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/term"

	"github.com/hossein1376/kamune/pkg/attest"
	"github.com/hossein1376/kamune/pkg/store"
)

type PassphraseHandler func() ([]byte, error)

func defaultPassphraseHandler() ([]byte, error) {
	fmt.Println("Enter passphrase:")
	pass, err := term.ReadPassword(0)
	if err != nil {
		return nil, err
	}
	return bytes.TrimSpace(pass), nil
}

type Storage struct {
	dbPath            string
	passphraseHandler PassphraseHandler
	identity          attest.Identity
	expiryDuration    time.Duration
	store             *store.Store
}

func openStorage(opts ...StorageOption) (*Storage, error) {
	s := &Storage{
		identity:          attest.Ed25519,
		passphraseHandler: defaultPassphraseHandler,
	}
	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, fmt.Errorf("applying option: %w", err)
		}
	}

	if s.dbPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("getting user's home directory: %w", err)
		}
		s.dbPath = filepath.Join(home, ".config", "kamune", "db")
	}

	pass, err := s.passphraseHandler()
	if err != nil {
		return nil, fmt.Errorf("getting passphrase: %w", err)
	}
	db, err := store.New(pass, s.dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening kamune db: %w", err)
	}
	s.store = db

	return s, nil
}

func (s *Storage) Close() error {
	return s.store.Close()
}

func (s *Storage) IsPeerKnown(claim []byte) bool {
	return s.store.PeerExists(claim)
}

func (s *Storage) TrustPeer(peer []byte) error {
	return s.store.AddPeer(peer, time.Now().Add(s.expiryDuration))
}

func (s *Storage) attester() (attest.Attester, error) {
	key := []byte(s.identity.String())
	id, err := s.store.GetIdentity(key)
	switch {
	case err == nil:
		return s.identity.Load(id)
	case errors.Is(err, store.ErrNotFound):
		// continue
	default:
		return nil, fmt.Errorf("getting identity: %w", err)
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	at, err := s.identity.NewAttest()
	if err != nil {
		return nil, fmt.Errorf("new %s: %w", s.identity, err)
	}
	data, err := at.Save()
	if err != nil {
		return nil, fmt.Errorf("saving key: %w", err)
	}
	err = s.store.AddIdentity(key, data)
	if err != nil {
		return nil, fmt.Errorf("persisting: %w", err)
	}

	return at, nil
}

type StorageOption func(*Storage) error

func StorageWithIdentity(identity attest.Identity) StorageOption {
	return func(p *Storage) error {
		p.identity = identity
		return nil
	}
}

func StorageWithDBPath(path string) StorageOption {
	return func(p *Storage) error {
		if p.dbPath != "" {
			return errors.New("already have db path")
		}
		p.dbPath = path
		return nil
	}
}

func StorageWithPassphraseHandler(fn PassphraseHandler) StorageOption {
	return func(p *Storage) error {
		p.passphraseHandler = fn
		return nil
	}
}
