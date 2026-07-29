package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/stretchr/testify/require"
)

type testListener struct {
	closed chan struct{}
	once   sync.Once
}

func newTestListener() *testListener {
	return &testListener{closed: make(chan struct{})}
}

func (l *testListener) Accept() (kamune.Conn, error) {
	<-l.closed
	return nil, net.ErrClosed
}

func (l *testListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

type echoPingTransport struct {
	pongCh chan<- []byte
}

func (t echoPingTransport) Send(
	message kamune.Transferable,
	_ kamune.Route,
) (*kamune.Metadata, error) {
	data := message.(interface{ GetValue() []byte }).GetValue()
	select {
	case t.pongCh <- append([]byte(nil), data...):
	default:
	}
	return nil, nil
}

func newQuietDaemon() *Daemon {
	d := NewDaemon()
	d.output = json.NewEncoder(io.Discard)
	return d
}

func TestSendPingDrainsStalePongBeforeSend(t *testing.T) {
	a := require.New(t)
	pongCh := make(chan []byte, 1)
	pongCh <- []byte("stale")

	err := sendPing(
		echoPingTransport{pongCh: pongCh},
		pongCh,
		100*time.Millisecond,
	)
	a.NoError(err)
}

func TestMultiListenerRejectsAddAfterClose(t *testing.T) {
	a := require.New(t)
	listener := newTestListener()
	multi := newMultiListener()
	a.NoError(multi.Add(listener))
	a.NoError(multi.Close())
	a.ErrorIs(multi.Add(newTestListener()), net.ErrClosed)
}

func TestMultiListenerConcurrentAddAndClose(t *testing.T) {
	a := require.New(t)
	multi := newMultiListener()
	const listenerCount = 32
	var wg sync.WaitGroup
	errs := make(chan error, listenerCount)
	wg.Add(listenerCount)
	for range listenerCount {
		go func() {
			defer wg.Done()
			listener := newTestListener()
			if err := multi.Add(listener); err != nil {
				errs <- err
				_ = listener.Close()
			}
		}()
	}
	_ = multi.Close()
	wg.Wait()
	close(errs)
	for err := range errs {
		a.ErrorIs(err, net.ErrClosed)
	}
}

func TestStopP2PResourcesClosesAndCancels(t *testing.T) {
	a := require.New(t)
	d := newQuietDaemon()
	listener := newTestListener()
	tokenCtx, tokenCancel := context.WithCancel(context.Background())

	d.p2pListener = listener
	d.p2pTokens = []p2pToken{{
		Token:  "token",
		ctx:    tokenCtx,
		cancel: tokenCancel,
	}}

	d.stopP2PResources()

	select {
	case <-listener.closed:
	default:
		t.Fatal("p2p listener was not closed")
	}
	select {
	case <-tokenCtx.Done():
	default:
		t.Fatal("p2p token context was not cancelled")
	}
	a.Nil(d.p2pListener)
	a.Empty(d.p2pTokens)
}

func TestLiveSessionStopCancelsReconnect(t *testing.T) {
	a := require.New(t)
	reconnectCtx, reconnectCancel := context.WithCancel(context.Background())
	session := &liveSession{
		reconnectCtx:    reconnectCtx,
		reconnectCancel: reconnectCancel,
		reconnectFn: func(string) (*kamune.Transport, error) {
			return nil, errors.New("must not reconnect")
		},
		keepAliveDone: make(chan struct{}),
	}

	a.Nil(session.stop())
	select {
	case <-reconnectCtx.Done():
	default:
		t.Fatal("reconnect context was not cancelled")
	}
	session.mu.Lock()
	a.Nil(session.reconnectFn)
	session.mu.Unlock()
	select {
	case <-session.keepAliveDone:
	default:
		t.Fatal("keepalive was not stopped")
	}
}

func TestHandleCloseSessionCancelsReconnect(t *testing.T) {
	a := require.New(t)
	d := newQuietDaemon()
	reconnectCtx, reconnectCancel := context.WithCancel(context.Background())
	receiveDone := make(chan struct{})
	close(receiveDone)
	session := &liveSession{
		ID:              "session",
		ReceiveDone:     receiveDone,
		reconnectCtx:    reconnectCtx,
		reconnectCancel: reconnectCancel,
		reconnectFn: func(string) (*kamune.Transport, error) {
			return nil, errors.New("must not reconnect")
		},
		keepAliveDone: make(chan struct{}),
	}
	d.sessions[session.ID] = session
	params, err := json.Marshal(CloseSessionParams{SessionID: session.ID})
	a.NoError(err)

	d.handleCloseSession(Command{ID: "close", Params: params})

	select {
	case <-reconnectCtx.Done():
	default:
		t.Fatal("reconnect context was not cancelled")
	}
	a.NotContains(d.sessions, session.ID)
}

func TestOpenStoragePreservesActiveStoreOnFailure(t *testing.T) {
	a := require.New(t)
	d := newQuietDaemon()
	t.Cleanup(func() {
		d.cancel()
		d.closeStore()
	})

	firstPath := filepath.Join(t.TempDir(), "first.db")
	a.NoError(d.openStorage(OpenStorageParams{
		StoragePath:    firstPath,
		DBNoPassphrase: true,
	}))
	first := d.store()
	a.NotNil(first)

	err := d.openStorage(OpenStorageParams{
		StoragePath:    t.TempDir(),
		DBNoPassphrase: true,
	})
	a.Error(err)
	a.Same(first, d.store())
}

func TestSubmitPassphraseUsesPendingStoragePath(t *testing.T) {
	a := require.New(t)
	d := newQuietDaemon()
	t.Cleanup(func() {
		d.cancel()
		d.closeStore()
	})
	t.Setenv("KAMUNE_DB_PASSPHRASE", "")

	path := filepath.Join(t.TempDir(), "encrypted.db")
	err := d.openStorage(OpenStorageParams{StoragePath: path})
	a.ErrorIs(err, errPassphraseRequired)
	a.Equal(path, d.pendingDBPath)

	params, err := json.Marshal(SubmitPassphraseParams{
		Passphrase: "test-passphrase",
	})
	a.NoError(err)
	d.handleSubmitPassphrase(Command{ID: "submit", Params: params})

	a.NotNil(d.store())
	a.Equal(path, d.dbPath)
	a.Empty(d.pendingDBPath)
}

func TestOpenStorageRejectedWhileSessionIsActive(t *testing.T) {
	a := require.New(t)
	d := newQuietDaemon()
	d.sessions["active"] = &liveSession{ID: "active"}

	err := d.openStorage(OpenStorageParams{
		StoragePath:    filepath.Join(t.TempDir(), "busy.db"),
		DBNoPassphrase: true,
	})
	a.ErrorIs(err, errStorageBusy)
	a.Nil(d.store())
}

func TestP2PDialDoesNotBlockCommandHandler(t *testing.T) {
	a := require.New(t)
	d := newQuietDaemon()
	t.Cleanup(func() {
		d.cancel()
		d.wg.Wait()
		d.closeStore()
	})
	a.NoError(d.openStorage(OpenStorageParams{
		StoragePath:    filepath.Join(t.TempDir(), "dial.db"),
		DBNoPassphrase: true,
	}))
	params, err := json.Marshal(DialParams{
		Transport:  "p2p",
		BrokerAddr: "invalid-broker-address",
	})
	a.NoError(err)

	returned := make(chan struct{})
	go func() {
		d.handleDial(Command{ID: "dial", Params: params})
		close(returned)
	}()

	select {
	case <-returned:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("handleDial blocked the command loop")
	}
}
