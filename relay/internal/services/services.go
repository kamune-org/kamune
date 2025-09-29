package services

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/relay/internal/config"
	"github.com/kamune-org/kamune/relay/internal/model"
	"github.com/kamune-org/kamune/relay/internal/storage"
)

const (
	attestation = "attestation"
)

var (
	attestationKey = []byte(attestation)
)

type Service struct {
	store    model.Store
	attester attest.Attester
	cfg      config.Config
}

func New(store *storage.Store, cfg config.Config) (*Service, error) {
	at, err := loadAttest(store, cfg.Identity)
	if err != nil {
		return nil, fmt.Errorf("loading attester: %w", err)
	}
	fp := strings.Join(fingerprint.Emoji(at.PublicKey().Marshal()), " • ")
	slog.Info("loaded identity", slog.String("fingerprint", fp))
	return &Service{store: store, attester: at, cfg: cfg}, nil
}

func loadAttest(
	store *storage.Store, id attest.Identity,
) (attest.Attester, error) {
	var at attest.Attester
	err := store.Command(func(c model.Command) error {
		attestBytes, err := c.Get(attestationKey)
		if err != nil {
			return fmt.Errorf("getting data from storage: %w", err)
		}
		at, err = id.Load(attestBytes)
		if err != nil {
			return fmt.Errorf("parsing data: %w", err)
		}
		return nil
	})
	switch {
	case err == nil:
		return at, nil
	case errors.Is(err, storage.ErrMissing):
		slog.Warn("no identity found, creating a new one...")
		// continue
	default:
		return nil, fmt.Errorf("command: %w", err)
	}

	at, err = id.NewAttest()
	if err != nil {
		return nil, fmt.Errorf("creating new attester: %w", err)
	}
	data, err := at.Save()
	if err != nil {
		return nil, fmt.Errorf("marshalling attester: %w", err)
	}
	err = store.Command(func(c model.Command) error {
		return c.Set(attestationKey, data)
	})
	if err != nil {
		return nil, fmt.Errorf("storing attester: %w", err)
	}

	return at, nil
}
