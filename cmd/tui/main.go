package main

import (
	"bufio"
	"fmt"
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

	pass := os.Getenv("KAMUNE_DB_PASSPHRASE")
	if pass == "" {
		fmt.Print("Passphrase: ")
		passBytes, err := term.ReadPassword(0)
		fmt.Println()
		if err != nil {
			slog.Error("reading passphrase", "error", err)
			os.Exit(1)
		}
		pass = string(passBytes)
	}

	store, err := storage.OpenStorage(
		storage.WithDBPath(dbPath),
		storage.WithPassphraseHandler(func() ([]byte, error) {
			return []byte(pass), nil
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

	if _, err := p.Run(); err != nil {
		slog.Error("program run", "error", err)
	}
}
