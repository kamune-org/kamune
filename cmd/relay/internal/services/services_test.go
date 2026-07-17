package services

import (
	"context"
	"testing"
	"time"

	"github.com/kamune-org/kamune/cmd/relay/internal/config"
	"github.com/stretchr/testify/require"
)

// validConfig returns a config that passes cfg.Validate. Tests mutate
// individual fields to exercise defaults applied by services.New.
func validConfig() config.Config {
	return config.Config{
		Server: config.Server{
			Password: "",
		},
		Diagnose: config.Diagnose{
			Enabled: true,
			Address: "127.0.0.1:0",
		},
		WS: config.WS{
			Enabled: true,
			Address: "127.0.0.1:0",
		},
		TCP: config.TCP{
			Enabled: true,
			Address: "127.0.0.1:0",
		},
		TLS: config.TLS{
			Enabled: true,
			Address: "127.0.0.1:0",
		},
		Session: config.Session{
			TokenTTL:              5 * time.Minute,
			SessionTTL:            30 * time.Minute,
			HandshakeTimeout:      30 * time.Second,
			MaxConcurrentSessions: 100,
			MaxMessageSize:        65536,
		},
		RateLimit: config.RateLimit{
			// Disabled is false by default — rate limit is on.
			TimeWindow: time.Minute,
			Quota:      20,
		},
	}
}

func TestServices_New_ValidConfig(t *testing.T) {
	a := require.New(t)
	s, err := New(context.Background(), validConfig())
	a.NoError(err, "New")
	a.NotNil(s, "service is nil")
	a.NotNil(s.Hub(), "Hub is nil")
}

// Defaults are applied by services.New, not by cfg.Validate; that is
// why these tests live here rather than in the config package.
func TestServices_New_DefaultsHandshakeTimeout(t *testing.T) {
	a := require.New(t)
	cfg := validConfig()
	cfg.Session.HandshakeTimeout = 0 // unset → 30s default
	s, err := New(context.Background(), cfg)
	a.NoError(err, "New")
	a.Equal(30*time.Second, s.Hub().HandshakeTimeout())
}

func TestServices_New_DisablesHandshakeTimeout(t *testing.T) {
	a := require.New(t)
	cfg := validConfig()
	cfg.Session.HandshakeTimeout = -1 // negative → disabled (0)
	s, err := New(context.Background(), cfg)
	a.NoError(err, "New")
	a.Equal(time.Duration(0), s.Hub().HandshakeTimeout())
}

// Verify the wrapping applied by services.New: a validation error from
// cfg.Validate is wrapped with an "invalid config:" prefix.
func TestServices_New_WrapsValidationError(t *testing.T) {
	a := require.New(t)
	cfg := validConfig()
	cfg.Session.MaxConcurrentSessions = 0
	_, err := New(context.Background(), cfg)
	a.Error(err, "expected error, got nil")
	a.Contains(err.Error(), "invalid config")
	a.Contains(err.Error(), "max_concurrent_sessions")
}
