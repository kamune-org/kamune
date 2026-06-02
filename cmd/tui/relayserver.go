package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/relayconn"
	"github.com/kamune-org/kamune/pkg/storage"
)

func relayServer(relayAddr, password string) {
	store, err := storage.OpenStorage(
		storage.WithDBPath("./server.db"), storage.WithNoPassphrase(),
	)
	if err != nil {
		errCh <- fmt.Errorf("opening storage: %w", err)
		return
	}
	defer store.Close()

	ctx := context.Background()
	var relayOpts []relayconn.Option
	if password != "" {
		relayOpts = append(relayOpts, relayconn.WithPassword(password))
	}
	listener, token, err := relayconn.ListenRelay(ctx, relayAddr, relayOpts...)
	if err != nil {
		errCh <- fmt.Errorf("relay listen: %w", err)
		return
	}

	fmt.Printf("Share this token with your peer: %x\n", token)

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

	srv, err := kamune.NewServer(relayAddr, handler, store,
		kamune.ServeWithListener(listener),
	)
	if err != nil {
		errCh <- fmt.Errorf("starting relay server: %w", err)
		return
	}
	pk := srv.PublicKey()
	fmt.Printf("Your base64 public key: %s\n", base64.RawURLEncoding.EncodeToString(pk))
	fmt.Printf("Starting relay server on %s\n", relayAddr)
	errCh <- srv.ListenAndServe()
}
