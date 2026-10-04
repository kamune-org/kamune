package handlers

import (
	"bytes"
	"context"
	"log"
	"log/slog"
	"sync"
	"time"
)

// rejectLogInterval is the least time between two "rate limit exceeded"
// lines. A rejection costs the client next to nothing, so logging every
// one would let a single client fill the relay's disk.
const rejectLogInterval = time.Second

// logSampler lets one event through per interval and counts the ones it
// holds back, so a flood of events costs a bounded amount of log.
type logSampler struct {
	mu         sync.Mutex
	next       time.Time
	interval   time.Duration
	suppressed int
}

// allow reports whether to log an event that happened at now, and how many
// events were held back since the last one it let through.
func (s *logSampler) allow(now time.Time) (bool, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now.Before(s.next) {
		s.suppressed++
		return false, 0
	}
	n := s.suppressed
	s.suppressed = 0
	s.next = now.Add(s.interval)
	return true, n
}

var rateLimitLog = &logSampler{interval: rejectLogInterval}

// logRateLimited logs that remote was refused by a rate limiter, at most
// once per rejectLogInterval across the relay.
func logRateLimited(remote string) {
	ok, suppressed := rateLimitLog.allow(time.Now())
	if !ok {
		return
	}
	slog.Warn(
		"rate limit exceeded",
		slog.String("remote", remote),
		slog.Int("suppressed", suppressed),
	)
}

// HTTPErrorLog returns a logger for an http.Server's ErrorLog. net/http
// writes a line there for every connection whose TLS handshake fails,
// which a client can cause at no cost, so those lines go to slog at debug.
// The rest, such as a handler panic or an accept error, are warnings.
func HTTPErrorLog() *log.Logger {
	return log.New(httpErrorWriter{}, "", 0)
}

// tlsHandshakeError starts net/http's line for a failed TLS handshake.
var tlsHandshakeError = []byte("http: TLS handshake error")

type httpErrorWriter struct{}

func (httpErrorWriter) Write(p []byte) (int, error) {
	level := slog.LevelWarn
	if bytes.HasPrefix(p, tlsHandshakeError) {
		level = slog.LevelDebug
	}
	slog.Log(
		context.Background(), level, "http server error",
		slog.String("error", string(bytes.TrimSuffix(p, []byte("\n")))),
	)
	return len(p), nil
}
