package logger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoggerInitWithValidPath tests logger initialization with a valid path
func TestLoggerInitWithValidPath(t *testing.T) {
	// Create a temporary directory for test logs
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	// Reset global state before test
	resetLogger()

	err := Init(logPath)
	if err != nil {
		t.Fatalf("Init failed with valid path: %v", err)
	}
	defer Close()

	// Verify file was created
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		t.Error("log file was not created")
	}
}

// TestLoggerInitDuplicate tests that duplicate Init calls are no-ops
func TestLoggerInitDuplicate(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	resetLogger()

	err := Init(logPath)
	if err != nil {
		t.Fatalf("first Init failed: %v", err)
	}

	// Second init should be a no-op
	err = Init(logPath + ".second")
	if err != nil {
		t.Fatalf("second Init should not fail: %v", err)
	}

	// Second file should not exist
	if _, err := os.Stat(logPath + ".second"); !os.IsNotExist(err) {
		t.Error("second log file should not be created")
	}

	Close()
}

// TestLoggerInfo tests Info logging
func TestLoggerInfo(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	resetLogger()

	err := Init(logPath)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	Info("test info message")
	Close()

	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}

	if !strings.Contains(string(content), "[INFO]") {
		t.Error("log should contain [INFO] tag")
	}

	if !strings.Contains(string(content), "test info message") {
		t.Error("log should contain the info message")
	}
}

// TestLoggerWarn tests Warn logging
func TestLoggerWarn(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	resetLogger()

	err := Init(logPath)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	Warn("test warning message")
	Close()

	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}

	if !strings.Contains(string(content), "[WARN]") {
		t.Error("log should contain [WARN] tag")
	}

	if !strings.Contains(string(content), "test warning message") {
		t.Error("log should contain the warning message")
	}
}

// TestLoggerError tests Error logging with error and context
func TestLoggerError(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	resetLogger()

	err := Init(logPath)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	testErr := os.ErrNotExist
	Error(testErr, "context message")
	Close()

	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}

	if !strings.Contains(string(content), "[ERROR]") {
		t.Error("log should contain [ERROR] tag")
	}

	if !strings.Contains(string(content), "context message") {
		t.Error("log should contain the context message")
	}
}

// TestLoggerErrorNilError tests Error logging with nil error
func TestLoggerErrorNilError(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	resetLogger()

	err := Init(logPath)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// This should not panic or cause issues
	Error(nil, "")
	Error(nil, "only context")
	Close()

	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}

	// "only context" should be logged
	if !strings.Contains(string(content), "only context") {
		t.Error("log should contain 'only context' when only context is provided")
	}
}

// TestLoggerErrorf tests Errorf logging
func TestLoggerErrorf(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	resetLogger()

	err := Init(logPath)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	Errorf("formatted error: %d %s", 42, "test")
	Close()

	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}

	if !strings.Contains(string(content), "[ERROR]") {
		t.Error("log should contain [ERROR] tag")
	}

	if !strings.Contains(string(content), "formatted error: 42 test") {
		t.Error("log should contain the formatted message")
	}
}

// TestLoggerWithoutInit tests that logging works without Init (falls back to stderr)
func TestLoggerWithoutInit(t *testing.T) {
	resetLogger()

	// These should not panic, they should use stderr fallback
	Info("fallback info")
	Warn("fallback warn")
	Error(nil, "fallback error context")
	Errorf("fallback errorf: %s", "message")
}

// TestLoggerClose tests closing the logger
func TestLoggerClose(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	resetLogger()

	err := Init(logPath)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	err = Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// Double close should be safe
	err = Close()
	if err != nil {
		t.Errorf("second Close should not fail: %v", err)
	}
}

// TestLoggerInitAfterClose tests that Init after Close fails
func TestLoggerInitAfterClose(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	resetLogger()

	err := Init(logPath)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	Close()

	// Init after close should fail
	err = Init(logPath + ".new")
	if err == nil {
		t.Error("Init after Close should fail")
	}
}

// TestLoggerTimestampFormat tests that logs contain RFC3339 timestamps
func TestLoggerTimestampFormat(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	resetLogger()

	err := Init(logPath)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	Info("timestamp test")
	Close()

	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}

	// RFC3339 format contains 'T' between date and time
	if !strings.Contains(string(content), "T") {
		t.Error("log should contain RFC3339 formatted timestamp")
	}
}

// TestLoggerInvalidPath tests Init with an invalid path
func TestLoggerInvalidPath(t *testing.T) {
	resetLogger()

	// Try to write to a non-existent directory
	err := Init("/nonexistent/directory/test.log")
	if err == nil {
		t.Error("Init should fail with invalid path")
		Close()
	}
}

// resetLogger resets global logger state for testing
func resetLogger() {
	mu.Lock()
	defer mu.Unlock()

	if file != nil {
		_ = file.Close()
		file = nil
	}
	l = nil
	closed = false
}

// BenchmarkInfo benchmarks Info logging
func BenchmarkInfo(b *testing.B) {
	tmpDir := b.TempDir()
	logPath := filepath.Join(tmpDir, "bench.log")

	resetLogger()
	if err := Init(logPath); err != nil {
		b.Fatalf("Init failed: %v", err)
	}
	defer Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Info("benchmark message")
	}
}

// BenchmarkErrorf benchmarks Errorf logging
func BenchmarkErrorf(b *testing.B) {
	tmpDir := b.TempDir()
	logPath := filepath.Join(tmpDir, "bench.log")

	resetLogger()
	if err := Init(logPath); err != nil {
		b.Fatalf("Init failed: %v", err)
	}
	defer Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Errorf("benchmark error: %d", i)
	}
}
