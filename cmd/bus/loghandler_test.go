package main

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// newTestLogger returns a logger whose records go to app's log buffer
// through an appLogHandler, and nowhere else.
func newTestLogger(app *App) *slog.Logger {
	stderr := slog.NewTextHandler(io.Discard, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	return slog.New(&appLogHandler{app: app, stderr: stderr})
}

// TestAppLogHandler_Level checks the log viewer level each slog level
// gets.
func TestAppLogHandler_Level(t *testing.T) {
	tests := []struct {
		level slog.Level
		want  string
	}{
		{level: slog.LevelDebug, want: "DEBUG"},
		{level: slog.LevelDebug + 2, want: "DEBUG"},
		{level: slog.LevelInfo, want: "INFO"},
		{level: slog.LevelInfo + 2, want: "INFO"},
		{level: slog.LevelWarn, want: "WARN"},
		{level: slog.LevelError, want: "ERROR"},
		{level: slog.LevelError + 4, want: "ERROR"},
	}
	for _, tt := range tests {
		t.Run(tt.level.String(), func(t *testing.T) {
			a := require.New(t)
			app := &App{logBufferSize: 10}
			newTestLogger(app).Log(t.Context(), tt.level, "message")
			a.Len(app.logEntries, 1)
			a.Equal(tt.want, app.logEntries[0].Level)
		})
	}
}

// TestAppLogHandler_Attrs checks that the log buffer gets the attributes
// a logger binds with With and WithGroup, as well as the record's own.
func TestAppLogHandler_Attrs(t *testing.T) {
	a := require.New(t)
	app := &App{logBufferSize: 10}
	logger := newTestLogger(app).With("base", 1).
		WithGroup("g").With("k", "v").WithGroup("h")
	logger.Info("message", "x", 2)
	a.Len(app.logEntries, 1)
	msg := app.logEntries[0].Message
	a.True(strings.HasSuffix(msg, "message | base=1 g.k=v g.h.x=2"), msg)

	// A logger derived later does not change the earlier one.
	_ = logger.With("y", 3)
	logger.Info("again")
	a.True(strings.HasSuffix(app.logEntries[1].Message,
		"again | base=1 g.k=v"), app.logEntries[1].Message)
}
