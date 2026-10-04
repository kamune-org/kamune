package services

import (
	"bytes"
	"context"
	"log/slog"
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

// TestServices_New_HandshakeTimeout checks that handshake_timeout = 0
// means the default, not "no limit": the timeout is the only bound on a
// connection that never registers.
func TestServices_New_HandshakeTimeout(t *testing.T) {
	tests := []struct {
		timeout, want time.Duration
	}{
		{timeout: 0, want: config.DefaultHandshakeTimeout},
		{timeout: 5 * time.Second, want: 5 * time.Second},
	}
	for _, tc := range tests {
		a := require.New(t)
		cfg := validConfig()
		cfg.Session.HandshakeTimeout = tc.timeout
		ctx, cancel := context.WithCancel(context.Background())
		s, err := New(ctx, cfg)
		a.NoError(err, "New")
		a.Equal(tc.want, s.Hub().HandshakeTimeout())
		cancel()
	}
}

func TestServices_New_RejectsNegativeHandshakeTimeout(t *testing.T) {
	a := require.New(t)
	cfg := validConfig()
	cfg.Session.HandshakeTimeout = -1
	_, err := New(context.Background(), cfg)
	a.Error(err, "expected error for negative handshake timeout")
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

// TestServices_New_LogsAuthMode checks that startup says whether PSK auth
// is on, so a relay that lost its password is noticed.
func TestServices_New_LogsAuthMode(t *testing.T) {
	tests := []struct {
		name     string
		password string
		want     string
	}{
		{name: "open", want: "psk auth off"},
		{name: "psk", password: "s3cret", want: "psk auth on"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			var out bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&out, nil)))
			t.Cleanup(func() { slog.SetDefault(prev) })

			cfg := validConfig()
			cfg.Server.Password = tc.password
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			_, err := New(ctx, cfg)
			a.NoError(err)
			a.Contains(out.String(), tc.want)
			if tc.password != "" {
				a.NotContains(out.String(), tc.password)
			}
		})
	}
}

// TestServices_New_MaxMessageSize checks that max_message_size = 0 means
// the default, which the ws and tcp handlers then read, not "no limit".
func TestServices_New_MaxMessageSize(t *testing.T) {
	tests := []struct {
		size, want int
	}{
		{size: 0, want: config.DefaultMaxMessageSize},
		{size: config.MaxMaxMessageSize, want: config.MaxMaxMessageSize},
	}
	for _, tc := range tests {
		a := require.New(t)
		cfg := validConfig()
		cfg.Session.MaxMessageSize = tc.size
		ctx, cancel := context.WithCancel(context.Background())
		s, err := New(ctx, cfg)
		a.NoError(err)
		a.Equal(tc.want, s.MaxMessageSize())
		a.Equal(tc.want, s.Hub().MaxMessageSize())
		cancel()
	}
}
