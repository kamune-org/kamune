package logger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoggerInitWithValidPath tests logger initialization with a valid path
func TestLoggerInitWithValidPath(t *testing.T) {
	a := assert.New(t)
	r := require.New(t)

	// Create a temporary directory for test logs
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	// Reset global state before test
	resetLogger()

	err := Init(logPath)
	r.NoError(err, "Init failed with valid path")
	defer Close()

	// Verify file was created
	_, err = os.Stat(logPath)
	a.False(os.IsNotExist(err), "log file was not created")
}

// TestLoggerInitDuplicate tests that duplicate Init calls are no-ops
func TestLoggerInitDuplicate(t *testing.T) {
	a := assert.New(t)
	r := require.New(t)

	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	resetLogger()

	err := Init(logPath)
	r.NoError(err, "first Init failed")

	// Second init should be a no-op
	err = Init(logPath + ".second")
	r.NoError(err, "second Init should not fail")

	// Second file should not exist
	_, err = os.Stat(logPath + ".second")
	a.True(os.IsNotExist(err), "second log file should not be created")

	Close()
}

// TestLoggerInfo tests Info logging
func TestLoggerInfo(t *testing.T) {
	a := assert.New(t)
	r := require.New(t)

	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	resetLogger()

	err := Init(logPath)
	r.NoError(err, "Init failed")

	Info("test info message")
	Close()

	content, err := os.ReadFile(logPath)
	r.NoError(err, "failed to read log file")

	a.True(strings.Contains(string(content), "[INFO]"), "log should contain [INFO] tag")
	a.True(strings.Contains(string(content), "test info message"), "log should contain the info message")
}

// TestLoggerWarn tests Warn logging
func TestLoggerWarn(t *testing.T) {
	a := assert.New(t)
	r := require.New(t)

	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	resetLogger()

	err := Init(logPath)
	r.NoError(err, "Init failed")

	Warn("test warning message")
	Close()

	content, err := os.ReadFile(logPath)
	r.NoError(err, "failed to read log file")

	a.True(strings.Contains(string(content), "[WARN]"), "log should contain [WARN] tag")
	a.True(strings.Contains(string(content), "test warning message"), "log should contain the warning message")
}

// TestLoggerError tests Error logging with error and context
func TestLoggerError(t *testing.T) {
	a := assert.New(t)
	r := require.New(t)

	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	resetLogger()

	err := Init(logPath)
	r.NoError(err, "Init failed")

	testErr := os.ErrNotExist
	Error(testErr, "context message")
	Close()

	content, err := os.ReadFile(logPath)
	r.NoError(err, "failed to read log file")

	a.True(strings.Contains(string(content), "[ERROR]"), "log should contain [ERROR] tag")
	a.True(strings.Contains(string(content), "context message"), "log should contain the context message")
}

// TestLoggerErrorNilError tests Error logging with nil error
func TestLoggerErrorNilError(t *testing.T) {
	a := assert.New(t)
	r := require.New(t)

	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	resetLogger()

	err := Init(logPath)
	r.NoError(err, "Init failed")

	// This should not panic or cause issues
	Error(nil, "")
	Error(nil, "only context")
	Close()

	content, err := os.ReadFile(logPath)
	r.NoError(err, "failed to read log file")

	// "only context" should be logged
	a.True(strings.Contains(string(content), "only context"), "log should contain 'only context' when only context is provided")
}

// TestLoggerErrorf tests Errorf logging
func TestLoggerErrorf(t *testing.T) {
	a := assert.New(t)
	r := require.New(t)

	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	resetLogger()

	err := Init(logPath)
	r.NoError(err, "Init failed")

	Errorf("formatted error: %d %s", 42, "test")
	Close()

	content, err := os.ReadFile(logPath)
	r.NoError(err, "failed to read log file")

	a.True(strings.Contains(string(content), "[ERROR]"), "log should contain [ERROR] tag")
	a.True(strings.Contains(string(content), "formatted error: 42 test"), "log should contain the formatted message")
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
	a := assert.New(t)
	r := require.New(t)

	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	resetLogger()

	err := Init(logPath)
	r.NoError(err, "Init failed")

	err = Close()
	a.NoError(err, "Close failed")

	// Double close should be safe
	err = Close()
	a.NoError(err, "second Close should not fail")
}

// TestLoggerInitAfterClose tests that Init after Close fails
func TestLoggerInitAfterClose(t *testing.T) {
	a := assert.New(t)
	r := require.New(t)

	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	resetLogger()

	err := Init(logPath)
	r.NoError(err, "Init failed")

	Close()

	// Init after close should fail
	err = Init(logPath + ".new")
	a.Error(err, "Init after Close should fail")
}

// TestLoggerTimestampFormat tests that logs contain RFC3339 timestamps
func TestLoggerTimestampFormat(t *testing.T) {
	a := assert.New(t)
	r := require.New(t)

	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	resetLogger()

	err := Init(logPath)
	r.NoError(err, "Init failed")

	Info("timestamp test")
	Close()

	content, err := os.ReadFile(logPath)
	r.NoError(err, "failed to read log file")

	// RFC3339 format contains 'T' between date and time
	a.True(strings.Contains(string(content), "T"), "log should contain RFC3339 formatted timestamp")
}

// TestLoggerInvalidPath tests Init with an invalid path
func TestLoggerInvalidPath(t *testing.T) {
	a := assert.New(t)

	resetLogger()

	// Try to write to a non-existent directory
	err := Init("/nonexistent/directory/test.log")
	a.Error(err, "Init should fail with invalid path")
	if err == nil {
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
	r := require.New(b)

	tmpDir := b.TempDir()
	logPath := filepath.Join(tmpDir, "bench.log")

	resetLogger()
	err := Init(logPath)
	r.NoError(err, "Init failed")
	defer Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Info("benchmark message")
	}
}

// BenchmarkErrorf benchmarks Errorf logging
func BenchmarkErrorf(b *testing.B) {
	r := require.New(b)

	tmpDir := b.TempDir()
	logPath := filepath.Join(tmpDir, "bench.log")

	resetLogger()
	err := Init(logPath)
	r.NoError(err, "Init failed")
	defer Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Errorf("benchmark error: %d", i)
	}
}
