package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

// LogEntry represents a single log entry with metadata
type LogEntry struct {
	Timestamp time.Time
	Level     string
	Message   string
}

// Simple concurrent file logger with in-app buffer support.
//
// Usage:
//
//	if err := logger.Init("./errors.log"); err != nil { /* fallback */ }
//	defer logger.Close()
//
//	logger.Info("starting up")
//	logger.Errorf("failed to do X: %v", err)
//	logger.Error(err, "context message")
//
// The logger writes to both stderr and the log file (append mode). It is safe
// to call concurrently from multiple goroutines. If Init is not called, the
// logger will fall back to writing to stderr.
//
// In-app log viewing:
//
//	entries := logger.GetEntries()     // Get all buffered log entries
//	logger.ClearEntries()              // Clear the buffer
//	logger.SetBufferSize(500)          // Adjust buffer size (default 200)
//	logger.Subscribe(func(e LogEntry){...})  // Subscribe to new entries
var (
	mu     sync.Mutex
	l      *log.Logger
	file   *os.File
	closed bool

	// In-app log buffer
	entries    []LogEntry
	bufferSize int = 200

	// Subscribers for real-time log updates
	subscribers   []func(LogEntry)
	subscribersMu sync.RWMutex
)

// Init initializes the logger to write to the provided path (append mode).
// If called multiple times, subsequent calls are no-ops.
func Init(path string) error {
	mu.Lock()
	defer mu.Unlock()

	if closed {
		return fmt.Errorf("logger: already closed")
	}

	if l != nil {
		// already initialized
		return nil
	}

	// Initialize entries buffer
	entries = make([]LogEntry, 0, bufferSize)

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		// Do not modify global logger; let ensure() fall back to stderr-based logger
		return err
	}

	file = f
	mw := io.MultiWriter(os.Stderr, file)
	l = log.New(mw, "", 0)
	l.Printf("%s - Logger initialized\n", time.Now().Format(time.RFC3339))
	return nil
}

// Close flushes and closes the underlying file (if any). After Close is
// called, Init can not be called again in this simple implementation.
func Close() error {
	mu.Lock()
	defer mu.Unlock()

	if closed {
		return nil
	}

	closed = true

	if l != nil {
		l.Printf("%s - Logger closing\n", time.Now().Format(time.RFC3339))
	}

	if file == nil {
		l = nil
		return nil
	}

	err := file.Close()
	file = nil
	l = nil
	return err
}

// ensure guarantees there is a usable logger (at least stderr).
func ensure() {
	// Note: caller must hold mu lock or this must be called under lock
	if l == nil {
		l = log.New(os.Stderr, "", 0)
	}
	if entries == nil {
		entries = make([]LogEntry, 0, bufferSize)
	}
}

// addEntry adds a log entry to the buffer and notifies subscribers
func addEntry(level, msg string) {
	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     level,
		Message:   msg,
	}

	// Add to buffer (under lock)
	if len(entries) >= bufferSize {
		// Remove oldest entry
		entries = entries[1:]
	}
	entries = append(entries, entry)

	// Notify subscribers (read lock for subscribers slice)
	subscribersMu.RLock()
	subs := make([]func(LogEntry), len(subscribers))
	copy(subs, subscribers)
	subscribersMu.RUnlock()

	for _, sub := range subs {
		go sub(entry)
	}
}

// GetEntries returns a copy of all buffered log entries
func GetEntries() []LogEntry {
	mu.Lock()
	defer mu.Unlock()

	if entries == nil {
		return []LogEntry{}
	}

	result := make([]LogEntry, len(entries))
	copy(result, entries)
	return result
}

// ClearEntries clears the log buffer
func ClearEntries() {
	mu.Lock()
	defer mu.Unlock()

	entries = make([]LogEntry, 0, bufferSize)
}

// SetBufferSize sets the maximum number of log entries to keep in memory
func SetBufferSize(size int) {
	mu.Lock()
	defer mu.Unlock()

	if size < 10 {
		size = 10
	}
	bufferSize = size

	// Trim existing entries if needed
	if entries != nil && len(entries) > bufferSize {
		entries = entries[len(entries)-bufferSize:]
	}
}

// GetBufferSize returns the current buffer size
func GetBufferSize() int {
	mu.Lock()
	defer mu.Unlock()
	return bufferSize
}

// Subscribe adds a callback that will be called for each new log entry.
// Returns an unsubscribe function.
func Subscribe(callback func(LogEntry)) func() {
	subscribersMu.Lock()
	subscribers = append(subscribers, callback)
	index := len(subscribers) - 1
	subscribersMu.Unlock()

	return func() {
		subscribersMu.Lock()
		defer subscribersMu.Unlock()
		// Mark as nil rather than removing to avoid index issues
		if index < len(subscribers) {
			subscribers[index] = nil
		}
	}
}

// FormatEntry formats a log entry as a string
func FormatEntry(e LogEntry) string {
	return fmt.Sprintf("%s [%s] %s", e.Timestamp.Format("15:04:05"), e.Level, e.Message)
}

// FormatEntryFull formats a log entry with full timestamp
func FormatEntryFull(e LogEntry) string {
	return fmt.Sprintf("%s [%s] %s", e.Timestamp.Format(time.RFC3339), e.Level, e.Message)
}

// Info logs an informational message.
func Info(msg string) {
	mu.Lock()
	defer mu.Unlock()

	ensure()
	l.Printf("%s [INFO] %s\n", time.Now().Format(time.RFC3339), msg)
	addEntry("INFO", msg)
}

// Infof logs a formatted informational message.
func Infof(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	mu.Lock()
	defer mu.Unlock()

	ensure()
	l.Printf("%s [INFO] %s\n", time.Now().Format(time.RFC3339), msg)
	addEntry("INFO", msg)
}

// Debug logs a debug message.
func Debug(msg string) {
	mu.Lock()
	defer mu.Unlock()

	ensure()
	l.Printf("%s [DEBUG] %s\n", time.Now().Format(time.RFC3339), msg)
	addEntry("DEBUG", msg)
}

// Debugf logs a formatted debug message.
func Debugf(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	mu.Lock()
	defer mu.Unlock()

	ensure()
	l.Printf("%s [DEBUG] %s\n", time.Now().Format(time.RFC3339), msg)
	addEntry("DEBUG", msg)
}

// Warn logs a warning message.
func Warn(msg string) {
	mu.Lock()
	defer mu.Unlock()

	ensure()
	l.Printf("%s [WARN] %s\n", time.Now().Format(time.RFC3339), msg)
	addEntry("WARN", msg)
}

// Warnf logs a formatted warning message.
func Warnf(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	mu.Lock()
	defer mu.Unlock()

	ensure()
	l.Printf("%s [WARN] %s\n", time.Now().Format(time.RFC3339), msg)
	addEntry("WARN", msg)
}

// Error logs an error with optional context and stack trace.
// If err is nil but context is non-empty, it logs the context anyway.
func Error(err error, context string) {
	if err == nil && context == "" {
		return
	}

	mu.Lock()
	defer mu.Unlock()

	ensure()

	var msg string
	if context != "" && err != nil {
		msg = fmt.Sprintf("%s: %v", context, err)
	} else if context != "" {
		msg = context
	} else {
		msg = err.Error()
	}

	l.Printf("%s [ERROR] %s\n", time.Now().Format(time.RFC3339), msg)
	addEntry("ERROR", msg)

	// Attach stack trace for additional debugging context (file only, not buffer)
	stack := debug.Stack()
	stackLines := strings.Split(string(stack), "\n")
	if len(stackLines) > 10 {
		stackLines = stackLines[:10]
	}
	l.Printf("%s\n", strings.Join(stackLines, "\n"))
}

// Errorf logs a formatted error message and a stack trace.
func Errorf(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)

	mu.Lock()
	defer mu.Unlock()

	ensure()
	l.Printf("%s [ERROR] %s\n", time.Now().Format(time.RFC3339), msg)
	addEntry("ERROR", msg)

	// Stack trace (file only, not buffer to keep it clean)
	stack := debug.Stack()
	stackLines := strings.Split(string(stack), "\n")
	if len(stackLines) > 10 {
		stackLines = stackLines[:10]
	}
	l.Printf("%s\n", strings.Join(stackLines, "\n"))
}
