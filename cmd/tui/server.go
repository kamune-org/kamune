package main

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
)

func server(addr string) {
	store, err := storage.OpenStorage(
		storage.WithDBPath("./server.db"), storage.WithNoPassphrase(),
	)
	if err != nil {
		errCh <- fmt.Errorf("opening storage: %w", err)
		return
	}
	defer store.Close()

	handler := func(t *kamune.Transport) error {
		msg, _ := checkMinorMismatch(kamune.AppVersion, t.RemotePeer().AppVersion)
		p := NewProgram(tea.NewProgram(initialModel(t, store, msg), tea.WithAltScreen()))
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
				switch {
				case errors.Is(err, kamune.ErrPeerDisconnected):
					fmt.Println("Peer disconnected")
					p.Quit()
					return nil
				case errors.Is(err, kamune.ErrConnClosed):
					p.Quit()
					return nil
				case errors.Is(err, kamune.ErrReceiveTimeout):
					continue
				default:
					errCh <- fmt.Errorf("receiving: %w", err)
					return nil
				}
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

	srv, err := kamune.NewServer(addr, handler, store)
	if err != nil {
		errCh <- fmt.Errorf("starting server: %w", err)
		return
	}
	fp := strings.Join(fingerprint.Emoji(srv.PublicKey()), " • ")
	fmt.Printf("Your emoji fingerprint: %s\n", fp)
	fmt.Printf("Starting server on %s\n", addr)
	errCh <- srv.ListenAndServe()
}
