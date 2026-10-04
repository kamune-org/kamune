package services

import (
	"context"
	"fmt"
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

func New(ctx context.Context, cfg config.Config) (*Service, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	slog.Info("starting relay service")
	// Say which mode the relay runs in, so a password that did not
	// reach the config shows up at once.
	if cfg.Server.Password != "" {
		slog.Info("psk auth on: clients must send server.password")
	} else {
		slog.Info("psk auth off: any client can register")
	}

	sessionTTL := cfg.Session.SessionTTL
	handshakeTimeout := cfg.Session.HandshakeTimeout
	if handshakeTimeout < 0 {
		handshakeTimeout = 0
	}

	sessions := NewSessionManager(
		cfg.Session.TokenTTL, cfg.Session.MaxConcurrentSessions, sessionTTL,
	)

	var rl *ratelimit.RateLimiter
	if cfg.RateLimit.IsEnabled() {
		// max_entries bounds the per-IP LRU cache. 0 means unbounded
		// (LRU mechanism off).
		rl = ratelimit.New(
			int(cfg.RateLimit.Quota),
			cfg.RateLimit.TimeWindow,
			cfg.RateLimit.MaxEntries,
		)
		slog.Info(
			"rate limiting enabled",
			slog.Int("quota", int(cfg.RateLimit.Quota)),
			slog.Duration("window", cfg.RateLimit.TimeWindow),
			slog.Int("max_entries", cfg.RateLimit.MaxEntries),
		)
	}

	maxMsgSize := cfg.Session.MaxMessageSize
	if maxMsgSize == 0 {
		maxMsgSize = config.DefaultMaxMessageSize
	}

	hub := NewHub(
		sessions,
		cfg.Server.Password,
		maxMsgSize,
		rl,
		handshakeTimeout,
	)

	go sessions.cleanupLoop(ctx)

	if sessionTTL > 0 {
		slog.Info("session ttl enabled", slog.Duration("ttl", sessionTTL))
	}
	if handshakeTimeout > 0 {
		slog.Info(
			"handshake timeout enabled",
			slog.Duration("timeout", handshakeTimeout),
		)
	}

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

func (s *Service) SessionTTL() time.Duration {
	return s.sessions.SessionTTL()
}

// MaxMessageSize returns the largest relay frame the relay reads from a
// client: session.max_message_size, or its default when that is 0.
func (s *Service) MaxMessageSize() int {
	return s.hub.MaxMessageSize()
}

func (s *Service) StartedAt() time.Time {
	return s.startedAt
}

func (s *Service) SessionCount() int {
	return s.sessions.Len()
}
