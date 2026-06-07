package services

import (
	"context"
	"log/slog"
	"time"

	"github.com/kamune-org/kamune/cmd/relay/internal/config"
	"github.com/kamune-org/kamune/cmd/relay/internal/ratelimit"
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

	var rl *ratelimit.RateLimiter
	if cfg.RateLimit.Enabled {
		maxEntries := cfg.RateLimit.MaxEntries
		if maxEntries <= 0 {
			maxEntries = cfg.Session.MaxConcurrentSessions
			if maxEntries <= 0 {
				maxEntries = 100000
			}
		}
		rl = ratelimit.New(
			int(cfg.RateLimit.Quota),
			cfg.RateLimit.TimeWindow,
			maxEntries,
		)
		slog.Info(
			"rate limiting enabled",
			slog.Int("quota", int(cfg.RateLimit.Quota)),
			slog.Duration("window", cfg.RateLimit.TimeWindow),
			slog.Int("max_entries", maxEntries),
		)
	}

	hub := NewHub(sessions, cfg.Server.Password, cfg.Session.MaxMessageSize, rl)

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
