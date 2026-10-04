package main

import (
	"bytes"
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

func TestStopP2PResourcesClosesListener(t *testing.T) {
	a := require.New(t)
	d := newQuietDaemon()
	listener := newTestListener()

	d.p2pListener = listener
	d.p2pTokens = []p2pToken{{Token: "token"}}

	d.stopP2PResources()

	select {
	case <-listener.closed:
	default:
		t.Fatal("p2p listener was not closed")
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

func TestFinishSessionEmitsSessionClosed(t *testing.T) {
	a := require.New(t)
	var buf bytes.Buffer
	d := NewDaemon()
	d.output = json.NewEncoder(&buf)
	session := &liveSession{
		ID: "s1", PeerName: "peer",
		ReceiveDone: make(chan struct{}),
	}
	d.sessions[session.ID] = session

	d.finishSession(session)

	a.NotContains(d.sessions, session.ID)
	a.Contains(buf.String(), `"session_closed"`)
}

func TestFinishSessionSkipsIfAlreadyRemoved(t *testing.T) {
	a := require.New(t)
	var buf bytes.Buffer
	d := NewDaemon()
	d.output = json.NewEncoder(&buf)
	d.finishSession(&liveSession{ID: "missing"})
	a.NotContains(buf.String(), "session_closed")
}

func TestParseVerAcceptsPrefixAndPrerelease(t *testing.T) {
	a := require.New(t)
	v, ok := parseVer("v1.2.3-dev")
	a.True(ok)
	a.Equal(1, v.major)
	a.Equal(2, v.minor)
	v, ok = parseVer("2.0")
	a.True(ok)
	a.Equal(2, v.major)
	a.Equal(0, v.minor)
}

func TestKeychainAccountUsesFullPath(t *testing.T) {
	a := require.New(t)
	a.Equal("db-passphrase:/tmp/a.db", keychainAccount("/tmp/a.db"))
	a.Equal("db-passphrase:default", keychainAccount(""))
}

func TestParseLogLevel(t *testing.T) {
	a := require.New(t)
	_, ok := parseLogLevel("debug")
	a.True(ok)
	_, ok = parseLogLevel("nope")
	a.False(ok)
}

func TestSessionInfoZeroLastActivityOmitsField(t *testing.T) {
	a := require.New(t)
	b, err := json.Marshal(SessionInfo{SessionID: "x", PeerName: "p"})
	a.NoError(err)
	var m map[string]any
	a.NoError(json.Unmarshal(b, &m))
	_, ok := m["last_activity"]
	a.False(ok)
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

func TestRemoveSessionPointerIdentity(t *testing.T) {
	a := require.New(t)
	d := newQuietDaemon()

	oldSession := &liveSession{ID: "sess-1"}
	newSession := &liveSession{ID: "sess-1"}

	d.mu.Lock()
	d.sessions["sess-1"] = newSession
	d.mu.Unlock()

	// finishSession with oldSession pointer should NOT remove newSession
	d.finishSession(oldSession)

	d.mu.RLock()
	cur, ok := d.sessions["sess-1"]
	d.mu.RUnlock()
	a.True(ok)
	a.Equal(newSession, cur)

	// finishSession with newSession pointer SHOULD remove it
	d.finishSession(newSession)

	d.mu.RLock()
	_, ok = d.sessions["sess-1"]
	d.mu.RUnlock()
	a.False(ok)
}

func TestHandleSendMessageDoesNotBlock(t *testing.T) {
	a := require.New(t)
	d := newQuietDaemon()

	session := &liveSession{
		ID:        "sess-1",
		Transport: nil,
	}
	d.mu.Lock()
	d.sessions["sess-1"] = session
	d.mu.Unlock()

	params, err := json.Marshal(SendMessageParams{
		SessionID:  "sess-1",
		DataBase64: "aGVsbG8=",
	})
	a.NoError(err)

	returned := make(chan struct{})
	go func() {
		d.handleCommand(Command{
			Type:   "cmd",
			CMD:    CmdSendMessage,
			ID:     "msg-1",
			Params: params,
		})
		close(returned)
	}()

	select {
	case <-returned:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("handleSendMessage blocked the command loop")
	}
}

func TestSubmitPassphraseRejectsEmptyPassphrase(t *testing.T) {
	a := require.New(t)
	d := NewDaemon()
	rec := newEventRecorder()
	d.output = json.NewEncoder(rec)
	t.Cleanup(func() {
		d.cancel()
		d.closeStore()
	})
	t.Setenv("KAMUNE_DB_PASSPHRASE", "")

	path := filepath.Join(t.TempDir(), "new.db")
	err := d.openStorage(OpenStorageParams{StoragePath: path})
	a.ErrorIs(err, errPassphraseRequired)

	d.handleSubmitPassphrase(Command{
		ID: "submit", Params: mustJSON(SubmitPassphraseParams{}),
	})

	evt := rec.waitFor(t, func(e recordedEvent) bool {
		return e.ID == "submit"
	})
	a.Equal(EvtError, evt.Evt)
	a.Equal("passphrase_required", evt.Data["code"])
	a.Nil(d.store())
	a.NoFileExists(path)
}

func TestReopenOpenStoragePath(t *testing.T) {
	// step opens the path again, with open or by submitting submit.
	type step struct {
		open       *OpenStorageParams
		submit     string
		wantFailed bool
	}
	tests := []struct {
		name    string
		first   OpenStorageParams
		envPass string
		again   step
	}{
		{
			name:  "open_storage again",
			first: OpenStorageParams{DBNoPassphrase: true},
			again: step{open: &OpenStorageParams{DBNoPassphrase: true}},
		},
		{
			name:    "submit_passphrase again",
			first:   OpenStorageParams{},
			envPass: "right",
			again:   step{submit: "right"},
		},
		{
			name:    "submit_passphrase with a wrong passphrase",
			first:   OpenStorageParams{},
			envPass: "right",
			again:   step{submit: "wrong", wantFailed: true},
		},
		{
			name:    "open_storage without the passphrase it needs",
			first:   OpenStorageParams{},
			envPass: "right",
			again: step{
				open:       &OpenStorageParams{DBNoPassphrase: true},
				wantFailed: true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			d := NewDaemon()
			rec := newEventRecorder()
			d.output = json.NewEncoder(rec)
			t.Cleanup(func() {
				d.cancel()
				d.closeStore()
			})
			t.Setenv("KAMUNE_DB_PASSPHRASE", tt.envPass)
			dir := t.TempDir()
			path := filepath.Join(dir, "kamune.db")
			tt.first.StoragePath = path
			a.NoError(d.openStorage(tt.first))
			pub, err := d.store().PublicKey()
			a.NoError(err)

			var failed bool
			if tt.again.open != nil {
				params := *tt.again.open
				// Another spelling of the same file.
				params.StoragePath = filepath.Join(dir, ".", "kamune.db")
				failed = d.openStorage(params) != nil
			} else {
				d.handleSubmitPassphrase(Command{
					ID: "submit",
					Params: mustJSON(SubmitPassphraseParams{
						Passphrase: tt.again.submit,
					}),
				})
				evt := rec.waitFor(t, func(e recordedEvent) bool {
					return e.ID == "submit"
				})
				failed = evt.Evt == EvtError
			}

			a.Equal(tt.again.wantFailed, failed)
			a.NotNil(d.store(), "no storage open")
			got, err := d.store().PublicKey()
			a.NoError(err)
			a.Equal(pub, got)
		})
	}
}
