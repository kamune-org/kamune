package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"log/slog"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/relayconn"
	"github.com/kamune-org/kamune/pkg/storage"
)

func relayClient(relayAddr, tokenHex, password string) {
	store, err := storage.OpenStorage(
		storage.WithDBPath("./client.db"), storage.WithNoPassphrase(),
	)
	if err != nil {
		errCh <- fmt.Errorf("opening storage: %w", err)
		return
	}
	defer store.Close()

	token, err := hex.DecodeString(tokenHex)
	if err != nil {
		errCh <- fmt.Errorf("decode token: %w", err)
		return
	}

	ctx := context.Background()

	var (
		t      *kamune.Transport
		dialer *kamune.Dialer
	)
	for {
		dialer, err = kamune.NewDialer(
			relayAddr,
			store,
			kamune.DialWithFunc(func(addr string) (kamune.Conn, error) {
				var dialOpts []relayconn.Option
				if password != "" {
					dialOpts = append(dialOpts, relayconn.WithPassword(password))
				}
				return relayconn.DialRelay(ctx, addr, token, dialOpts...)
			}),
		)
		if err != nil {
			errCh <- fmt.Errorf("create dialer: %w", err)
			return
		}

		t, err = dialer.Dial()
		if err == nil {
			break
		}
		log.Printf("relay dial retry: %v", err)
	}
	defer t.Close()

	msg, _ := checkMinorMismatch(kamune.AppVersion, t.RemotePeer().AppVersion)

	p := NewProgram(tea.NewProgram(initialModel(t, store, msg), tea.WithAltScreen()))
	go func() {
		if _, err := p.Run(); err != nil {
			errCh <- err
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
					return
				case errors.Is(err, kamune.ErrConnClosed):
					p.Quit()
					return
				case errors.Is(err, kamune.ErrReceiveTimeout):
					continue
				default:
					errCh <- fmt.Errorf("receiving: %w", err)
					return
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
