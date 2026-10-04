package main

import (
	"context"
	"log/slog"
	"runtime"
	"slices"
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
	// attrs are the attributes bound by WithAttrs, their keys qualified
	// by the groups opened before them. group is the prefix of the
	// groups opened by WithGroup, such as "a.b.".
	attrs []slog.Attr
	group string
}

// Enabled reports whether level is at least the app's log level, which
// SetLogLevel sets.
func (h *appLogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return level >= h.app.logLevelVar.Level() &&
		h.stderr.Enabled(ctx, level)
}

// levelLabel returns the log viewer's name for level: one of DEBUG,
// INFO, WARN and ERROR.
func levelLabel(level slog.Level) string {
	switch {
	case level >= slog.LevelError:
		return "ERROR"
	case level >= slog.LevelWarn:
		return "WARN"
	case level >= slog.LevelInfo:
		return "INFO"
	default:
		return "DEBUG"
	}
}

func (h *appLogHandler) Handle(ctx context.Context, r slog.Record) error {
	if err := h.stderr.Handle(ctx, r); err != nil {
		return err
	}

	pkg := callerPackage(r)
	msg := r.Message
	if pkg != "" {
		msg = "[" + pkg + "] " + msg
	}
	parts := make([]string, 0, len(h.attrs)+r.NumAttrs())
	for _, a := range h.attrs {
		parts = append(parts, a.Key+"="+a.Value.Resolve().String())
	}
	r.Attrs(func(a slog.Attr) bool {
		parts = append(parts,
			h.group+a.Key+"="+a.Value.Resolve().String())
		return true
	})
	if len(parts) > 0 {
		msg += " | " + strings.Join(parts, " ")
	}

	entry := LogEntryInfo{
		Timestamp: time.Now(),
		Level:     levelLabel(r.Level),
		Message:   escapeLogText(msg),
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

// WithAttrs returns a handler that adds attrs to every record, in the
// log buffer as well as on stderr.
func (h *appLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	n := *h
	n.stderr = h.stderr.WithAttrs(attrs)
	n.attrs = slices.Clone(h.attrs)
	for _, a := range attrs {
		a.Key = h.group + a.Key
		n.attrs = append(n.attrs, a)
	}
	return &n
}

// WithGroup returns a handler that puts the attributes added after it
// in the group name, in the log buffer as well as on stderr.
func (h *appLogHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	n := *h
	n.stderr = h.stderr.WithGroup(name)
	n.group = h.group + name + "."
	return &n
}
