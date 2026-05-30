package main

import (
	"fmt"
	"time"

	"github.com/kamune-org/kamune/pkg/storage"
)

// historyLoaded is sent once the background goroutine finishes reading prior
// chat entries from the database.
type historyLoaded struct {
	messages []string
}

// printHistory opens a local Bolt DB (preferring ./client.db then ./server.db),
// reads chat entries for the provided session ID, and prints timestamps + message
// payloads to stdout.
func printHistory(sessionID, dbPath string) error {
	if dbPath == "" {
		return fmt.Errorf("db path must be provided with -db flag")
	}

	var entries []storage.ChatEntry
	// Open kamune.Storage and get chat history.
	s, err := storage.OpenStorage(
		storage.WithDBPath(dbPath), storage.WithNoPassphrase(),
	)
	if err != nil {
		return fmt.Errorf("opening storage: %w", err)
	}
	defer s.Close()

	entries, err = s.GetChatHistory(sessionID)
	if err != nil {
		return fmt.Errorf("getting chat history: %w", err)
	}

	if len(entries) == 0 {
		fmt.Println("no chat entries found for session:", sessionID)
		return nil
	}

	for _, ent := range entries {
		sender := "You"
		if ent.Sender != storage.SenderLocal {
			sender = "Peer"
		}
		fmt.Printf(
			"%s: %s  %s\n",
			sender,
			ent.Timestamp.Format(time.DateTime),
			string(ent.Data),
		)
	}

	return nil
}
