package main

import (
	"net"
	"path/filepath"
	"sync"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/storage"
)

// pipeListener hands out one connection and then waits to be closed.
type pipeListener struct {
	conns  chan kamune.Conn
	closed chan struct{}
	once   sync.Once
}

func newPipeListener(c net.Conn) *pipeListener {
	l := &pipeListener{
		conns:  make(chan kamune.Conn, 1),
		closed: make(chan struct{}),
	}
	l.conns <- kamune.NewConn(c)
	return l
}

func (l *pipeListener) Accept() (kamune.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func openTestStore(t *testing.T) *storage.Storage {
	t.Helper()
	store, err := storage.OpenStorage(
		storage.WithDBPath(filepath.Join(t.TempDir(), "db")),
		storage.WithNoPassphrase(),
	)
	require.New(t).NoError(err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// dialPipe runs a kamune server with handler over an in-memory pipe and
// returns the dialer's side of the session.
func dialPipe(
	t *testing.T, handler func(*kamune.Transport) error,
) *kamune.Transport {
	t.Helper()
	a := require.New(t)
	accept := func(*storage.Storage, *storage.Peer) error { return nil }
	clientNet, serverNet := net.Pipe()

	srv, err := kamune.NewServer(
		"", handler, openTestStore(t), accept,
		kamune.ServeWithListener(newPipeListener(serverNet)),
	)
	a.NoError(err)
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = srv.ListenAndServe()
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		<-served
	})

	dialer, err := kamune.NewDialer(
		"", openTestStore(t), accept,
		kamune.DialWithFunc(func(string) (kamune.Conn, error) {
			return kamune.NewConn(clientNet), nil
		}),
	)
	a.NoError(err)
	tr, err := dialer.Dial()
	a.NoError(err)
	t.Cleanup(func() { _ = tr.CloseAbort() })
	return tr
}

func TestReceiveLoop_OnlyExchangeMessagesAreChat(t *testing.T) {
	a := require.New(t)
	tr := dialPipe(t, func(t *kamune.Transport) error {
		// Bus and the daemon send a SessionData frame first on every
		// session that is not incognito.
		_, err := t.Send(
			kamune.Bytes([]byte("\x0a\x0becdh_pubkey\x12\x01\x1b")),
			kamune.RouteSessionData,
		)
		if err != nil {
			return err
		}
		_, err = t.Send(
			kamune.Bytes([]byte("hello")), kamune.RouteExchangeMessages,
		)
		if err != nil {
			return err
		}
		return t.Close()
	})

	var got []tea.Msg
	receiveLoop(tr, make(chan []byte, 1), func(msg tea.Msg) {
		got = append(got, msg)
	})

	a.Len(got, 2)
	chat, ok := got[0].(chatMessageMsg)
	a.True(ok, "first message is %T", got[0])
	a.Equal("hello", chat.text)
	a.Equal(storage.SenderPeer, chat.sender)
	a.IsType(peerDisconnectedMsg{}, got[1])
}
