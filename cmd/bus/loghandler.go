package main

import (
	"context"
	"log/slog"
	"runtime"
	"strings"
	"time"
)

const modulePrefix = "github.com/kamune-org/kamune/"

// callerPackage extracts the package path from a slog Record's PC.
//
// runtime.FuncForPC returns names in these formats:
//
//	<package>.Func
//	<package>.(*Type).Method
//
// We strip the function/method and any type receiver to recover the bare
// import path, then trim the kamune module prefix for conciseness.
//
// Examples:
//
//	github.com/kamune-org/kamune.(*Server).serve   → kamune
//	github.com/kamune-org/kamune/server.handle      → server
//	github.com/kamune-org/kamune/pkg/storage.(*S).G → pkg/storage
//	fmt.Println                                      → fmt
func callerPackage(r slog.Record) string {
	fn := runtime.FuncForPC(r.PC)
	if fn == nil {
		return ""
	}
	name := fn.Name()

	// Strip ".(*Type)" if present (method on a type).
	if i := strings.Index(name, ".("); i >= 0 {
		name = name[:i]
	} else if i := strings.LastIndex(name, "."); i >= 0 {
		// Bare function — strip the function name after the last dot.
		name = name[:i]
	}

	// Shorten kamune module paths.
	if name == "github.com/kamune-org/kamune" {
		return "kamune"
	}
	if trimmed, ok := strings.CutPrefix(name, modulePrefix); ok {
		return trimmed
	}
	return name
}

// appLogHandler is a slog.Handler that:
//  1. Writes to stderr via the underlying text handler.
//  2. Stores the entry in the App's in-memory log buffer.
//  3. Emits the entry to the Wails frontend via EventsEmit.
//
// This captures all slog calls from any package (including kamune core) and
// makes them visible in the bus log viewer.
type appLogHandler struct {
	app    *App
	stderr slog.Handler
}

func (h *appLogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.stderr.Enabled(ctx, level)
}

func (h *appLogHandler) Handle(ctx context.Context, r slog.Record) error {
	if err := h.stderr.Handle(ctx, r); err != nil {
		return err
	}

	var level string
	switch {
	case r.Level >= slog.LevelError:
		level = "ERROR"
	case r.Level >= slog.LevelWarn:
		level = "WARN"
	case r.Level >= slog.LevelDebug:
		level = "DEBUG"
	default:
		level = "INFO"
	}

	pkg := callerPackage(r)
	msg := r.Message
	if pkg != "" {
		msg = "[" + pkg + "] " + msg
	}
	first := true
	r.Attrs(func(a slog.Attr) bool {
		if first {
			msg += " |"
			first = false
		}
		msg += " " + a.Key + "=" + a.Value.String()
		return true
	})

	entry := LogEntryInfo{
		Timestamp: time.Now(),
		Level:     level,
		Message:   msg,
	}

	h.app.logMu.Lock()
	h.app.logEntries = append(h.app.logEntries, entry)
	if len(h.app.logEntries) > h.app.logBufferSize {
		h.app.logEntries = h.app.logEntries[len(h.app.logEntries)-h.app.logBufferSize:]
	}
	h.app.logMu.Unlock()

	h.app.emitEvent("log-entry", entry)

	return nil
}

func (h *appLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &appLogHandler{
		app:    h.app,
		stderr: h.stderr.WithAttrs(attrs),
	}
}

func (h *appLogHandler) WithGroup(name string) slog.Handler {
	return &appLogHandler{
		app:    h.app,
		stderr: h.stderr.WithGroup(name),
	}
}
