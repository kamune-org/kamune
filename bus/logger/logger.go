package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"runtime/debug"
	"sync"
	"time"
)

// Simple concurrent file logger.
//
// Usage:
//
//	if err := logger.Init(\"./errors.log\"); err != nil { /* fallback */ }
//	defer logger.Close()
//
//	logger.Info(\"starting up\")
//	logger.Errorf(\"failed to do X: %v\", err)
//	logger.Error(err, \"context message\")
//
// The logger writes to both stderr and the log file (append mode). It is safe
// to call concurrently from multiple goroutines. If Init is not called, the
// logger will fall back to writing to stderr.
var (
	mu     sync.Mutex
	l      *log.Logger
	file   *os.File
	closed bool
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
	mu.Lock()
	defer mu.Unlock()
	if l == nil {
		l = log.New(os.Stderr, "", 0)
	}
}

// Info logs an informational message.
func Info(msg string) {
	ensure()
	l.Printf("%s [INFO] %s\n", time.Now().Format(time.RFC3339), msg)
}

// Warn logs a warning message.
func Warn(msg string) {
	ensure()
	l.Printf("%s [WARN] %s\n", time.Now().Format(time.RFC3339), msg)
}

// Error logs an error with optional context and stack trace.
// If err is nil but context is non-empty, it logs the context anyway.
func Error(err error, context string) {
	if err == nil && context == "" {
		return
	}
	ensure()
	if context != "" && err != nil {
		l.Printf("%s [ERROR] %s: %v\n", time.Now().Format(time.RFC3339), context, err)
	} else if context != "" {
		l.Printf("%s [ERROR] %s\n", time.Now().Format(time.RFC3339), context)
	} else {
		l.Printf("%s [ERROR] %v\n", time.Now().Format(time.RFC3339), err)
	}
	// Attach stack trace for additional debugging context
	stack := debug.Stack()
	l.Printf("%s\n", string(stack))
}

// Errorf logs a formatted error message and a stack trace.
func Errorf(format string, a ...interface{}) {
	ensure()
	l.Printf("%s [ERROR] %s\n", time.Now().Format(time.RFC3339), fmt.Sprintf(format, a...))
	l.Printf("%s\n", string(debug.Stack()))
}
