package services

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/pkg/fingerprint"

	"github.com/kamune-org/kamune/relay/internal/config"
	"github.com/kamune-org/kamune/relay/internal/model"
	"github.com/kamune-org/kamune/relay/internal/storage"
)

var (
	attestationKey = []byte("attestation")
	identityNS     = model.NewNameSpace("identity")
)

type Service struct {
	store     model.Store
	attest    *attest.Attest
	cfg       config.Config
	startedAt time.Time
	hub       *Hub
	webhooks  *WebhookRegistry
	metrics   *Metrics
}

func New(store model.Store, cfg config.Config) (*Service, error) {
	at, err := loadAttest(store)
	if err != nil {
		return nil, fmt.Errorf("loading attester: %w", err)
	}
	fp := strings.Join(fingerprint.Emoji(at.MarshalPublicKey()), " • ")
	slog.Info("loaded identity", slog.String("fingerprint", fp))
	return &Service{
		store:     store,
		attest:    at,
		cfg:       cfg,
		startedAt: time.Now(),
		hub:       NewHub(),
		webhooks:  NewWebhookRegistry(),
		metrics:   NewMetrics(),
	}, nil
}

// MaxMessageSize returns the configured maximum message size in bytes.
// A value of 0 means unlimited.
func (s *Service) MaxMessageSize() int {
	return s.cfg.Storage.MaxMessageSize
}

func loadAttest(store model.Store) (*attest.Attest, error) {
	var at *attest.Attest
	err := store.Command(func(c model.Command) error {
		attestBytes, err := c.Get(identityNS, attestationKey)
		if err != nil {
			return fmt.Errorf("getting data from storage: %w", err)
		}
		at, err = attest.Load(attestBytes)
		if err != nil {
			return fmt.Errorf("parsing data: %w", err)
		}
		return nil
	})
	switch {
	case err == nil:
		return at, nil
	case errors.Is(err, storage.ErrMissing):
		slog.Info("no identity found, creating a new one...")
		// continue
	default:
		return nil, fmt.Errorf("command: %w", err)
	}

	at, err = attest.New()
	if err != nil {
		return nil, fmt.Errorf("creating new attester: %w", err)
	}
	data, err := at.Save()
	if err != nil {
		return nil, fmt.Errorf("marshalling attester: %w", err)
	}
	err = store.Command(func(c model.Command) error {
		return c.Set(identityNS, attestationKey, data)
	})
	if err != nil {
		return nil, fmt.Errorf("storing attester: %w", err)
	}

	return at, nil
}
