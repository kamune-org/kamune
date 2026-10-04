package handlers

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLogSampler(t *testing.T) {
	a := require.New(t)
	s := &logSampler{interval: time.Second}
	t0 := time.Unix(1_700_000_000, 0)
	steps := []struct {
		at         time.Duration
		ok         bool
		suppressed int
	}{
		{at: 0, ok: true, suppressed: 0},
		{at: 100 * time.Millisecond, ok: false},
		{at: 999 * time.Millisecond, ok: false},
		{at: time.Second, ok: true, suppressed: 2},
		{at: 1500 * time.Millisecond, ok: false},
		{at: 5 * time.Second, ok: true, suppressed: 1},
		{at: 7 * time.Second, ok: true, suppressed: 0},
	}
	for _, st := range steps {
		ok, n := s.allow(t0.Add(st.at))
		a.Equal(st.ok, ok, "at %s", st.at)
		a.Equal(st.suppressed, n, "at %s", st.at)
	}
}

func TestWebSocketHandler_RejectionsDoNotFloodLog(t *testing.T) {
	a := require.New(t)
	out := captureLog(t, slog.LevelInfo)

	cfg := testConfig(1)
	cfg.Server.TrustedProxies = []string{"127.0.0.0/8"}
	h := newTestHandler(t, cfg)

	const requests = 500
	for i := range requests {
		r := newRequest(
			"127.0.0.1:1234", headerLine{"X-Forwarded-For", "203.0.113.9"},
		)
		w := httptest.NewRecorder()
		h.WebSocketHandler(w, r)
		if i > 0 {
			a.Equal(http.StatusTooManyRequests, w.Code)
		}
	}

	logged := out.String()
	a.False(
		strings.Contains(logged, "failed to accept"),
		"a request that is not an upgrade is logged at debug",
	)
	a.Less(
		strings.Count(logged, "rate limit exceeded"), requests/10,
		"rejections must be sampled, not logged one by one",
	)
}

func TestHTTPErrorLog(t *testing.T) {
	tests := []struct {
		name  string
		line  string
		level string
	}{
		{
			name:  "tls handshake error",
			line:  "http: TLS handshake error from 192.0.2.1:1234: EOF",
			level: "level=DEBUG",
		},
		{
			name:  "handler panic",
			line:  "http: panic serving 192.0.2.1:1234: boom",
			level: "level=WARN",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			out := captureLog(t, slog.LevelDebug)
			HTTPErrorLog().Print(tc.line)

			var found string
			for line := range strings.Lines(out.String()) {
				if strings.Contains(line, tc.line) {
					found = line
				}
			}
			a.NotEmpty(found, "the line must be logged")
			a.Contains(found, tc.level)
		})
	}
}
