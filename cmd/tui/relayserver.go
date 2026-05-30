package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/cmd/tui/internal/relayconn"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
)

func relayServer(relayAddr string) {
	store, err := storage.OpenStorage(
		storage.WithDBPath("./server.db"), storage.WithNoPassphrase(),
	)
	if err != nil {
		errCh <- fmt.Errorf("opening storage: %w", err)
		return
	}
	defer store.Close()

	at, err := store.Attester()
	if err != nil {
		errCh <- fmt.Errorf("loading attester: %w", err)
		return
	}
	selfKey := at.MarshalPublicKey()

	ctx := context.Background()
	listener, err := relayconn.ListenRelay(ctx, relayAddr, selfKey)
	if err != nil {
		errCh <- fmt.Errorf("relay listen: %w", err)
		return
	}

	handler := func(t *kamune.Transport) error {
		p := NewProgram(tea.NewProgram(initialModel(t, store), tea.WithAltScreen()))
		go func() {
			if _, err := p.Run(); err != nil {
				panic(err)
			}
			stop <- struct{}{}
		}()

		for {
			b := kamune.Bytes(nil)
			metadata, err := t.Receive(b)
			if err != nil {
				if errors.Is(err, kamune.ErrConnClosed) {
					p.Quit()
					return nil
				}
				errCh <- fmt.Errorf("receiving: %w", err)
				return nil
			}
			p.Send(NewMessage(metadata.Timestamp(), b.GetValue()))
			if err := store.AddChatEntry(
				t.SessionID(),
				b.GetValue(),
				metadata.Timestamp(),
				storage.SenderPeer,
			); err != nil {
				slog.Error(
					"failed to persist received chat entry",
					slog.String("session_id", t.SessionID()),
					slog.Any("error", err),
				)
			}
		}
	}

	srv, err := kamune.NewServer(relayAddr, handler, store,
		kamune.ServeWithListener(listener),
	)
	if err != nil {
		errCh <- fmt.Errorf("starting relay server: %w", err)
		return
	}
	pk := srv.PublicKey()
	fp := strings.Join(fingerprint.Emoji(pk), " • ")
	fmt.Printf("Your emoji fingerprint: %s\n", fp)
	fmt.Printf("Your base64 public key: %s\n", base64.RawURLEncoding.EncodeToString(pk))
	fmt.Printf("Starting relay server on %s\n", relayAddr)
	errCh <- srv.ListenAndServe()
}
