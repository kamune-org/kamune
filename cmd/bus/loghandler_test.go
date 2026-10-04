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
			app.SetLogLevel("DEBUG")
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

// TestLogLevel_Filters checks that the log level setting decides which
// lines the app keeps, from slog and from addLogEntry alike, which it
// prints on stderr, and which it exports.
func TestLogLevel_Filters(t *testing.T) {
	levels := []string{"DEBUG", "INFO", "WARN", "ERROR"}
	for i, setting := range levels {
		t.Run(setting, func(t *testing.T) {
			a := require.New(t)
			app := &App{logBufferSize: 50}
			var stderr strings.Builder
			logger := slog.New(&appLogHandler{
				app: app,
				stderr: slog.NewTextHandler(&stderr, &slog.HandlerOptions{
					Level: slog.LevelDebug,
				}),
			})
			app.SetLogLevel(setting)
			a.Equal(setting, app.GetLogLevel())

			for _, lvl := range levels {
				l, ok := parseLogLevel(lvl)
				a.True(ok)
				logger.Log(t.Context(), l, "slog "+lvl)
				app.addLogEntry(lvl, "entry "+lvl)
			}
			var got []string
			for _, e := range app.logEntries {
				got = append(got, e.Level)
			}
			var want []string
			for _, lvl := range levels[i:] {
				want = append(want, lvl, lvl)
			}
			a.Equal(want, got)
			a.Equal(len(levels)-i, strings.Count(stderr.String(), "msg="))
			a.Len(app.exportedLogEntries(), len(want))
		})
	}
}

// TestLogLevel_Unknown checks that SetLogLevel ignores a level the log
// viewer does not have.
func TestLogLevel_Unknown(t *testing.T) {
	a := require.New(t)
	app := &App{logBufferSize: 50, logLevel: "INFO"}
	app.SetLogLevel("TRACE")
	a.Equal("INFO", app.GetLogLevel())
	a.Equal(slog.LevelInfo, app.logLevelVar.Level())
}

// TestExportedLogEntries checks that an export leaves out the lines kept
// before the log level was raised.
func TestExportedLogEntries(t *testing.T) {
	a := require.New(t)
	app := &App{logBufferSize: 50}
	app.SetLogLevel("DEBUG")
	app.addLogEntry("DEBUG", "debug")
	app.addLogEntry("WARN", "warn")
	app.SetLogLevel("WARN")
	got := app.exportedLogEntries()
	a.Len(got, 1)
	a.Equal("WARN", got[0].Level)
}
