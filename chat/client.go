package main

import (
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"strings"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
)

func client(addr string) {
	var dialOpts []storage.StorageOption
	dialOpts = append(
		dialOpts, storage.WithDBPath("./client.db"), storage.WithNoPassphrase(),
	)

	dialer, err := kamune.NewDialer(
		addr,
		kamune.DialWithStorageOpts(dialOpts...),
	)
	if err != nil {
		errCh <- fmt.Errorf("create new dialer: %w", err)
		return
	}
	defer dialer.Close()

	fp := strings.Join(fingerprint.Emoji(dialer.PublicKey()), " • ")
	fmt.Printf("Your emoji fingerprint: %s\n", fp)

	var t *kamune.Transport
	for {
		var opErr *net.OpError
		var err error
		t, err = dialer.Dial()
		if err == nil {
			break
		}
		if errors.As(err, &opErr) && errors.Is(opErr.Err, syscall.ECONNREFUSED) {
			time.Sleep(2 * time.Second)
			continue
		}
		log.Printf("dial err: %v", err)
		time.Sleep(5 * time.Second)
	}
	defer t.Close()

	p := NewProgram(tea.NewProgram(initialModel(t), tea.WithAltScreen()))
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
