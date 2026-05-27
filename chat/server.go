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
	var opts []storage.StorageOption
	opts = append(
		opts, storage.WithDBPath("./server.db"), storage.WithNoPassphrase(),
	)

	srv, err := kamune.NewServer(
		addr, serveHandler, kamune.ServeWithStorageOpts(opts...),
	)
	if err != nil {
		errCh <- fmt.Errorf("starting server: %w", err)
		return
	}
	fp := strings.Join(fingerprint.Emoji(srv.PublicKey()), " • ")
	fmt.Printf("Your emoji fingerprint: %s\n", fp)
	fmt.Printf("Starting server on %s\n", addr)
	errCh <- srv.ListenAndServe()
}

func serveHandler(t *kamune.Transport) error {
	p := NewProgram(tea.NewProgram(initialModel(t), tea.WithAltScreen()))
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
		if err := t.Store().AddChatEntry(
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
