package main

import (
	"fmt"
	"log"
	"log/slog"
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

// logFileEnv names the environment variable that holds the path of a file
// the TUI appends its log to while the UI runs. When it is unset, the log
// is dropped while the UI runs.
const logFileEnv = "KAMUNE_TUI_LOG"

// runUI runs p with the default slog logger writing to the file at logPath,
// or dropping every record when logPath is empty. While the UI runs, the
// terminal belongs to Bubble Tea, and a record written to stderr, such as
// the one the server logs for every failed inbound handshake, would land in
// the middle of the screen. When p returns, the default logger and the
// output and flags of the log package are put back as they were, since
// slog.SetDefault sends the log package through the new logger.
func runUI(p *tea.Program, logPath string) error {
	logger, closeLog, err := uiLogger(logPath)
	if err != nil {
		return err
	}
	prev := slog.Default()
	prevOut, prevFlags := log.Writer(), log.Flags()
	slog.SetDefault(logger)
	defer func() {
		slog.SetDefault(prev)
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
		closeLog()
	}()
	_, err = p.Run()
	return err
}

// uiLogger returns the logger for runUI and a function that releases it.
// The log file is created if needed and readable only by its owner, since
// the log names peers and sessions.
func uiLogger(path string) (*slog.Logger, func(), error) {
	if path == "" {
		return slog.New(slog.DiscardHandler), func() {}, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("opening log file: %w", err)
	}
	return slog.New(slog.NewTextHandler(f, nil)), func() { _ = f.Close() }, nil
}
