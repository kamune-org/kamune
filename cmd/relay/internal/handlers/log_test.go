package handlers

import (
	"bytes"
	"log/slog"
	"sync"
	"testing"
)

// syncBuffer is a bytes.Buffer safe for a slog handler shared by
// goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureLog sends the default logger's records at level and above to the
// returned buffer until t ends.
func captureLog(t *testing.T, level slog.Level) *syncBuffer {
	t.Helper()
	out := &syncBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(
		out, &slog.HandlerOptions{Level: level},
	)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return out
}
