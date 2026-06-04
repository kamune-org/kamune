package services

import (
	"context"
	"log/slog"
	"time"

	"github.com/kamune-org/kamune/cmd/relay/internal/config"
)

type Service struct {
	hub       *Hub
	sessions  *SessionManager
	cfg       config.Config
	startedAt time.Time
}

func New(cfg config.Config) (*Service, error) {
	slog.Info("starting relay service")
	sessions := NewSessionManager(cfg.Session.TokenTTL, cfg.Session.MaxConcurrentSessions)
	hub := NewHub(sessions, cfg.Server.Password, cfg.Session.MaxMessageSize)

	go sessions.cleanupLoop(context.Background())

	return &Service{
		hub:       hub,
		sessions:  sessions,
		cfg:       cfg,
		startedAt: time.Now(),
	}, nil
}

func (s *Service) Hub() *Hub {
	return s.hub
}

func (s *Service) TokenTTL() time.Duration {
	return s.sessions.TTL()
}

func (s *Service) MaxMessageSize() int {
	return s.cfg.Session.MaxMessageSize
}

func (s *Service) StartedAt() time.Time {
	return s.startedAt
}

func (s *Service) SessionCount() int {
	return s.sessions.Len()
}
