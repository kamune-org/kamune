package handlers

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/cmd/relay/internal/config"
	"github.com/kamune-org/kamune/cmd/relay/internal/services"
)

// testConfig returns a config that passes Validate, with the rate limiter
// on at the given quota (0 turns it off).
func testConfig(quota uint64) config.Config {
	return config.Config{
		WS: config.WS{Enabled: true, Address: "127.0.0.1:0"},
		Session: config.Session{
			TokenTTL:              time.Minute,
			MaxConcurrentSessions: 100,
		},
		RateLimit: config.RateLimit{
			Disabled:   quota == 0,
			TimeWindow: time.Minute,
			Quota:      quota,
			MaxEntries: 100,
		},
	}
}

// newTestHandler builds a Handler over a real Service for cfg.
func newTestHandler(t *testing.T, cfg config.Config) *Handler {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srvc, err := services.New(ctx, cfg)
	require.New(t).NoError(err)
	return New(srvc, cfg)
}

func TestHandler_ClientIPHeaderFromConfig(t *testing.T) {
	tests := []struct {
		name   string
		header string
		lines  []headerLine
		want   string
	}{
		{
			name:  "unset reads x-forwarded-for",
			lines: []headerLine{{"X-Real-Ip", "203.0.113.99"}, {"X-Forwarded-For", "198.51.100.7"}},
			want:  "198.51.100.7",
		},
		{
			name:   "lower case name is canonicalized",
			header: "cf-connecting-ip",
			lines:  []headerLine{{"X-Forwarded-For", "203.0.113.99"}, {"CF-Connecting-IP", "198.51.100.7"}},
			want:   "198.51.100.7",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			cfg := testConfig(0)
			cfg.Server.TrustedProxies = []string{"127.0.0.0/8"}
			cfg.Server.ClientIPHeader = tc.header
			h := newTestHandler(t, cfg)
			r := newRequest("127.0.0.1:1234", tc.lines...)
			a.Equal(tc.want, h.clientIP(r))
		})
	}
}
