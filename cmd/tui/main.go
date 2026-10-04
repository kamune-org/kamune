package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/kamune-org/kamune/pkg/storage"
	"golang.org/x/term"
)

func main() {
	changePass := flag.Bool("change-passphrase", false,
		"set a new database passphrase and exit")
	noPass := flag.Bool("no-passphrase", false,
		"open or create the database without a passphrase, without "+
			"asking;\nanyone who can copy the database file can read it")
	flag.Parse()
	given, err := givenPassphrase(os.Getenv(passphraseEnv), *noPass)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v.\n", err)
		os.Exit(1)
	}

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

	pr := prompter{
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
			// Fd 0 is not the console handle on Windows.
			return term.ReadPassword(int(os.Stdin.Fd()))
		},
	}
	store, pass, err := openDB(dbPath, given, pr)
	if errors.Is(err, storage.ErrWrongPassphrase) {
		if *noPass {
			fmt.Fprintf(os.Stderr, "The database at %s has a passphrase; "+
				"start without -no-passphrase.\n", dbPath)
		} else {
			fmt.Fprintf(os.Stderr,
				"The passphrase does not open the database at %s.\n",
				dbPath,
			)
		}
		os.Exit(1)
	}
	if err != nil {
		slog.Error("opening storage", "error", err)
		os.Exit(1)
	}
	if *changePass {
		err := changePassphrase(store, pass, pr)
		_ = store.Close()
		if errors.Is(err, storage.ErrReopen) {
			fmt.Fprintf(os.Stderr, "The new passphrase is in effect, but "+
				"the database could not be opened again: %v\n", err)
			os.Exit(1)
		}
		if err != nil {
			slog.Error("changing passphrase", "error", err)
			os.Exit(1)
		}
		return
	}
	defer store.Close()

	m := &model{store: store, state: stateWelcome, s: defaultStyles()}
	p := tea.NewProgram(m)
	m.program = p

	if err := runUI(p, os.Getenv(logFileEnv)); err != nil {
		slog.Error("program run", "error", err)
	}
}
