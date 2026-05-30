package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/cmd/tui/internal/relayconn"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
)

func relayClient(relayAddr, peerKeyB64 string) {
	store, err := storage.OpenStorage(
		storage.WithDBPath("./client.db"), storage.WithNoPassphrase(),
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
	peerKey, err := base64.RawURLEncoding.DecodeString(peerKeyB64)
	if err != nil {
		errCh <- fmt.Errorf("decode peer key: %w", err)
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
				return relayconn.DialRelay(ctx, addr, selfKey, peerKey)
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

	pk := dialer.PublicKey()
	fp := strings.Join(fingerprint.Emoji(pk), " • ")
	fmt.Printf("Your emoji fingerprint: %s\n", fp)
	fmt.Printf("Your base64 public key: %s\n", base64.RawURLEncoding.EncodeToString(pk))

	p := NewProgram(tea.NewProgram(initialModel(t, store), tea.WithAltScreen()))
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
			if errors.Is(err, kamune.ErrConnClosed) {
				p.Quit()
				return
			}
			errCh <- fmt.Errorf("receiving: %w", err)
			return
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
