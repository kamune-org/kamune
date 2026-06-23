package services

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kamune-org/kamune/cmd/relay/internal/config"
)

// validConfig returns a config that passes cfg.Validate. Tests mutate
// individual fields to exercise defaults applied by services.New.
func validConfig() config.Config {
	return config.Config{
		Server: config.Server{
			Address:      "127.0.0.1:0",
			Password:     "",
			ExposeHealth: true,
			ExposeIP:     true,
		},
		Session: config.Session{
			TokenTTL:              5 * time.Minute,
			SessionTTL:            30 * time.Minute,
			HandshakeTimeout:      30 * time.Second,
			MaxConcurrentSessions: 100,
			MaxMessageSize:        65536,
		},
		RateLimit: config.RateLimit{
			Enabled: false,
		},
	}
}

func TestServices_New_ValidConfig(t *testing.T) {
	s, err := New(context.Background(), validConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s == nil {
		t.Fatal("service is nil")
	}
	if s.Hub() == nil {
		t.Error("Hub is nil")
	}
}

// Defaults are applied by services.New, not by cfg.Validate; that is
// why these tests live here rather than in the config package.
func TestServices_New_DefaultsHandshakeTimeout(t *testing.T) {
	cfg := validConfig()
	cfg.Session.HandshakeTimeout = 0 // unset → 30s default
	s, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := s.Hub().HandshakeTimeout(); got != 30*time.Second {
		t.Errorf("HandshakeTimeout = %v, want 30s", got)
	}
}

func TestServices_New_DisablesHandshakeTimeout(t *testing.T) {
	cfg := validConfig()
	cfg.Session.HandshakeTimeout = -1 // negative → disabled (0)
	s, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := s.Hub().HandshakeTimeout(); got != 0 {
		t.Errorf("HandshakeTimeout = %v, want 0 (disabled)", got)
	}
}

// Verify the wrapping applied by services.New: a validation error from
// cfg.Validate is wrapped with an "invalid config:" prefix.
func TestServices_New_WrapsValidationError(t *testing.T) {
	cfg := validConfig()
	cfg.Session.MaxConcurrentSessions = 0
	_, err := New(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	got := err.Error()
	if !strings.Contains(got, "invalid config") ||
		!strings.Contains(got, "max_concurrent_sessions") {
		t.Errorf("err = %q, want it to contain 'invalid config' and 'max_concurrent_sessions'", got)
	}
}
