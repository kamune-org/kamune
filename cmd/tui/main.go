package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/kamune-org/kamune/pkg/storage"
	"golang.org/x/term"
)

func main() {
	fmt.Println("╔══════════════════════════════╗")
	fmt.Println("║      Kamune Chat (TUI)        ║")
	fmt.Println("╚══════════════════════════════╝")
	fmt.Println()

	dbPath := os.Getenv("KAMUNE_DB_PATH")
	if dbPath == "" {
		if home, err := os.UserHomeDir(); err == nil {
			dbPath = filepath.Join(home, ".config", "kamune", "db")
		} else {
			dbPath = "./kamune.db"
		}
	}

	scanner := bufio.NewScanner(os.Stdin)
	fmt.Printf("Database path [%s]: ", dbPath)
	if scanner.Scan() {
		if input := strings.TrimSpace(scanner.Text()); input != "" {
			dbPath = input
		}
	}
	if err := scanner.Err(); err != nil {
		slog.Error("reading db path", "error", err)
		os.Exit(1)
	}

	pass := []byte(os.Getenv("KAMUNE_DB_PASSPHRASE"))
	if len(pass) == 0 {
		_, statErr := os.Stat(dbPath)
		p := prompter{
			out: os.Stdout,
			readLine: func() (string, error) {
				if scanner.Scan() {
					return scanner.Text(), nil
				}
				if err := scanner.Err(); err != nil {
					return "", err
				}
				return "", io.EOF
			},
			readSecret: func() ([]byte, error) {
				return term.ReadPassword(0)
			},
		}
		var err error
		pass, err = p.passphrase(errors.Is(statErr, fs.ErrNotExist))
		if err != nil {
			slog.Error("reading passphrase", "error", err)
			os.Exit(1)
		}
	}

	store, err := storage.OpenStorage(
		storage.WithDBPath(dbPath),
		storage.WithPassphraseHandler(func() ([]byte, error) {
			return pass, nil
		}),
	)
	if err != nil {
		slog.Error("opening storage", "error", err)
		os.Exit(1)
	}
	defer store.Close()

	m := &model{store: store, state: stateWelcome, s: defaultStyles()}
	p := tea.NewProgram(m)
	m.program = p

	if err := runUI(p, os.Getenv(logFileEnv)); err != nil {
		slog.Error("program run", "error", err)
	}
}
