package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/storage"
)

// liveSessionByID returns the first session of app with ID id, or nil.
func liveSessionByID(app *App, id string) *liveSession {
	app.mu.RLock()
	defer app.mu.RUnlock()
	for _, s := range app.sessions {
		if s.ID == id {
			return s
		}
	}
	return nil
}

// newServerTestApp returns an unlocked app that admits every peer and
// runs a TCP server, and the server's address.
func newServerTestApp(t *testing.T) (*App, string) {
	t.Helper()
	a := require.New(t)
	app, _ := newUnlockedApp(t, "secret")
	app.mu.Lock()
	app.verifMode = VerificationModeAutoAccept
	app.mu.Unlock()
	addr := freeTCPAddr(t)
	_, _, err := app.StartServer(
		addr, "tcp", "", "srv", "", "", "", false, false, "",
	)
	a.NoError(err)
	t.Cleanup(func() { _ = app.StopServer() })
	return app, addr
}

// dialTestServer dials the server at addr with a dialer on store, retrying
// until the server listens.
func dialTestServer(
	t *testing.T, addr string, store *storage.Storage, opts ...kamune.DialOption,
) *kamune.Transport {
	t.Helper()
	a := require.New(t)
	opts = append([]kamune.DialOption{kamune.DialWithTCP()}, opts...)
	var tr *kamune.Transport
	a.Eventually(func() bool {
		d, err := kamune.NewDialer(addr, store, acceptAll, opts...)
		if err != nil {
			return false
		}
		tr, err = d.Dial()
		return err == nil
	}, testWait, 10*time.Millisecond)
	t.Cleanup(func() { _ = tr.CloseAbort() })
	return tr
}

// receiveChat reads from tr until a chat message arrives and returns its
// text.
func receiveChat(t *testing.T, tr *kamune.Transport) string {
	t.Helper()
	a := require.New(t)
	a.NoError(tr.SetDeadline(time.Now().Add(testWait)))
	for {
		md, payload, err := tr.ReceivePayload()
		a.NoError(err)
		if md.Route() != kamune.RouteExchangeMessages {
			continue
		}
		b := kamune.Bytes(nil)
		a.NoError(proto.Unmarshal(payload, b))
		return string(b.GetValue())
	}
}

// TestResumedServerSessionReplacesStaleOne resumes a server session on a
// new connection while the old one is still open, as a peer does after
// its network changes, and checks that the resumed session takes the old
// one's place: the old connection is closed, the app lists the session
// once, and messages go out on the new connection.
func TestResumedServerSessionReplacesStaleOne(t *testing.T) {
	a := require.New(t)
	app, addr := newServerTestApp(t)
	dialStore := openTestStorage(t)

	first := dialTestServer(t, addr, dialStore)
	id := first.SessionID()
	// A resumption checks the server against its stored key.
	a.NoError(dialStore.StorePeer(first.RemotePeer()))
	var stale *liveSession
	a.Eventually(func() bool {
		stale = liveSessionByID(app, id)
		return stale != nil
	}, testWait, time.Millisecond)

	resumed := dialTestServer(
		t, addr, dialStore, kamune.DialWithResume(id),
	)
	a.Equal(id, resumed.SessionID())

	a.Eventually(func() bool {
		s := liveSessionByID(app, id)
		return s != nil && s != stale
	}, testWait, time.Millisecond, "the resumed session must replace the old one")
	select {
	case <-stale.ReceiveDone:
	case <-time.After(testWait):
		t.Fatal("the old connection of the session was not closed")
	}
	sessions := app.GetSessions()
	a.Len(sessions, 1)
	a.Equal(id, sessions[0].ID)

	a.NoError(app.SendMessage(id, "hello"))
	a.Equal("hello", receiveChat(t, resumed))

	a.NoError(first.SetDeadline(time.Now().Add(testWait)))
	for {
		if _, _, err := first.ReceivePayload(); err != nil {
			a.ErrorIs(err, kamune.ErrConnClosed)
			break
		}
	}
}

// countingListener counts the connections it accepts.
type countingListener struct {
	net.Listener
	accepted atomic.Int32
}

func (l *countingListener) Accept() (kamune.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.accepted.Add(1)
	return kamune.NewConn(c), nil
}

// startCountingServer runs a kamune server that admits every peer and
// reads each session until it ends. It returns the server's address and
// its listener.
func startCountingServer(t *testing.T) (string, *countingListener) {
	t.Helper()
	a := require.New(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	a.NoError(err)
	cl := &countingListener{Listener: ln}
	srv, err := kamune.NewServer(
		"", readUntilEnd, openTestStorage(t), acceptAll,
		kamune.ServeWithListener(cl),
	)
	a.NoError(err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.ListenAndServe()
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		<-done
	})
	return ln.Addr().String(), cl
}

// TestClosedDialedSessionDoesNotReconnect closes a dialed session on
// purpose and checks that its receive loop ends without dialing the peer
// again to resume it.
func TestClosedDialedSessionDoesNotReconnect(t *testing.T) {
	cases := []struct {
		name  string
		close func(app *App, id string) error
	}{
		{"stop server", func(app *App, _ string) error {
			return app.StopServer()
		}},
		{"disconnect session", func(app *App, id string) error {
			return app.DisconnectSession(id)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			app, _ := newUnlockedApp(t, "secret")
			app.mu.Lock()
			app.verifMode = VerificationModeAutoAccept
			app.mu.Unlock()
			addr, ln := startCountingServer(t)

			res, err := app.ConnectToServer(
				addr, "tcp", "", "", "", "", "", "", "", false, false, "",
			)
			a.NoError(err)
			session := liveSessionByID(app, res.SessionID)
			a.NotNil(session)
			a.NotNil(session.reconnectFn)

			a.NoError(tc.close(app, res.SessionID))
			select {
			case <-session.ReceiveDone:
			case <-time.After(testWait):
				t.Fatal("the receive loop of the closed session did not end")
			}
			a.EqualValues(1, ln.accepted.Load(),
				"a closed session must not dial its peer again")
			a.Empty(app.GetSessions())
		})
	}
}

// faultConn is a connection whose reads fail with err once it is cut, as
// a reset or an unreachable host would make them.
type faultConn struct {
	net.Conn
	err    error
	cut    atomic.Bool
	closed atomic.Bool
}

// cutOff makes every later read fail with c.err, and ends a read in
// progress.
func (c *faultConn) cutOff() {
	c.cut.Store(true)
	_ = c.Conn.Close()
}

func (c *faultConn) Read(b []byte) (int, error) {
	if c.cut.Load() {
		return 0, c.err
	}
	n, err := c.Conn.Read(b)
	if err != nil && c.cut.Load() {
		return 0, c.err
	}
	return n, err
}

func (c *faultConn) SetDeadline(t time.Time) error {
	if c.cut.Load() {
		return nil
	}
	return c.Conn.SetDeadline(t)
}

func (c *faultConn) SetReadDeadline(t time.Time) error {
	if c.cut.Load() {
		return nil
	}
	return c.Conn.SetReadDeadline(t)
}

func (c *faultConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

// TestLostConnectionReconnects cuts a dialed session's connection with a
// read error and checks that the session closes the dead connection and
// tries to resume, for a reset that the core reports as ErrConnClosed
// and for a socket error that it does not map.
func TestLostConnectionReconnects(t *testing.T) {
	cases := []struct {
		name string
		err  syscall.Errno
	}{
		{"connection reset", syscall.ECONNRESET},
		{"host unreachable", syscall.EHOSTUNREACH},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			app, _ := newUnlockedApp(t, "secret")
			addr, _ := startCountingServer(t)

			var fc *faultConn
			d, err := kamune.NewDialer(
				addr, openTestStorage(t), acceptAll,
				kamune.DialWithFunc(func(addr string) (kamune.Conn, error) {
					c, err := net.Dial("tcp", addr)
					if err != nil {
						return nil, err
					}
					fc = &faultConn{Conn: c, err: &net.OpError{
						Op: "read", Net: "tcp",
						Err: os.NewSyscallError("read", tc.err),
					}}
					return kamune.NewConn(fc), nil
				}),
			)
			a.NoError(err)
			tr, err := d.Dial()
			a.NoError(err)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			redialed := make(chan struct{})
			var once sync.Once
			session := &liveSession{
				ID:            tr.SessionID(),
				Transport:     tr,
				ReceiveDone:   make(chan struct{}),
				pongCh:        make(chan []byte, 1),
				keepAliveDone: make(chan struct{}),
				reconnectCtx:  ctx,
				reconnectFn: func(string) (*kamune.Transport, error) {
					once.Do(func() { close(redialed) })
					return nil, errors.New("test: no resumption")
				},
				reconnectCancel: cancel,
			}
			app.mu.Lock()
			app.sessions = append(app.sessions, session)
			app.mu.Unlock()
			go app.receiveMessages(session)

			fc.cutOff()
			select {
			case <-redialed:
			case <-time.After(testWait):
				t.Fatal("the session did not try to resume")
			}
			a.True(fc.closed.Load(), "the dead connection must be closed")

			cancel()
			select {
			case <-session.ReceiveDone:
			case <-time.After(testWait):
				t.Fatal("the receive loop did not end")
			}
		})
	}
}

// TestReconnectStopsOnPermanentError checks that a reconnect gives up at
// once on an error that a retry cannot fix, such as a resumption the peer
// rejected, and keeps trying after one that may pass, such as a network
// error.
func TestReconnectStopsOnPermanentError(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		wantRetry bool
	}{
		{"resumption rejected", fmt.Errorf("handshake: attempt resume: %w: %s",
			kamune.ErrResumptionRejected, "resumption not available"), false},
		{"no resumption token", fmt.Errorf("getting resumption token: %w",
			storage.ErrNotFound), false},
		{"session gone", fmt.Errorf("getting session peer: %w",
			storage.ErrSessionNotFound), false},
		{"peer expired", storage.ErrPeerExpired, false},
		{"no storage", kamune.ErrMissingStorage, false},
		{"network error", &net.OpError{
			Op: "dial", Net: "tcp",
			Err: os.NewSyscallError("connect", syscall.ECONNREFUSED),
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			app, cleanup := newTestAppWithStorage(t)
			defer cleanup()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var calls atomic.Int32
			session := &liveSession{
				ID:           "s",
				reconnectCtx: ctx,
				reconnectFn: func(string) (*kamune.Transport, error) {
					if calls.Add(1) > 1 {
						// A second attempt is all this test needs.
						cancel()
					}
					return nil, tc.err
				},
				reconnectCancel: cancel,
			}

			a.False(app.reconnectSession(session))
			if tc.wantRetry {
				a.Equal(int32(2), calls.Load())
			} else {
				a.Equal(int32(1), calls.Load())
				a.NoError(ctx.Err(), "the reconnect gave up on its own")
			}
		})
	}
}

// TestStopServerClosesVerificationPrompts stops a server while a peer
// waits for the user to verify it, and checks that the prompt closes and
// the peer is turned away.
func TestStopServerClosesVerificationPrompts(t *testing.T) {
	a := require.New(t)
	app, _ := newUnlockedApp(t, "secret")
	app.mu.Lock()
	app.verifMode = VerificationModeStrict
	app.mu.Unlock()
	events := recordEvents(app)
	addr := freeTCPAddr(t)
	_, _, err := app.StartServer(
		addr, "tcp", "", "srv", "", "", "", false, false, "",
	)
	a.NoError(err)

	// The server listens once StartServer returns.
	d, err := kamune.NewDialer(
		addr, openTestStorage(t), acceptAll, kamune.DialWithTCP(),
	)
	a.NoError(err)
	dialed := make(chan error, 1)
	go func() {
		tr, err := d.Dial()
		if err == nil {
			_ = tr.Close()
		}
		dialed <- err
	}()
	ids := waitPending(t, app, 1)

	a.NoError(app.StopServer())
	a.Eventually(func() bool {
		return len(pendingIDs(app)) == 0
	}, testWait, time.Millisecond, "the prompt must close with the server")
	a.Contains(events.closedIDs(), ids[0])
	select {
	case err := <-dialed:
		a.Error(err, "the peer must not be admitted")
	case <-time.After(testWait):
		t.Fatal("the dial did not end")
	}
	a.Empty(app.GetSessions())
}

// TestDisconnectSessionEndsResumption closes a dialed session on purpose
// and checks that its resumption tokens are gone, so that it cannot be
// resumed, and that an incognito session, which has none in storage,
// closes without a warning about them.
func TestDisconnectSessionEndsResumption(t *testing.T) {
	cases := []struct {
		name      string
		incognito bool
	}{
		{"saved session", false},
		{"incognito session", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			app, _ := newUnlockedApp(t, "secret")
			app.mu.Lock()
			app.verifMode = VerificationModeAutoAccept
			app.incognito = tc.incognito
			app.mu.Unlock()
			addr, _ := startTestServer(t, "srv", readUntilEnd)
			res, err := app.ConnectToServer(
				addr, "tcp", "", "", "", "", "", "", "", false, false, "",
			)
			a.NoError(err)
			store := app.store()
			if !tc.incognito {
				m, err := store.GetMeta(
					res.SessionID, storage.ResumptionTokensKey,
				)
				a.NoError(err)
				a.NotEmpty(m.Value(), "a saved session has tokens")
			}

			a.NoError(app.DisconnectSession(res.SessionID))

			m, err := store.GetMeta(res.SessionID, storage.ResumptionTokensKey)
			if err == nil {
				a.Empty(m.Value(), "a closed session keeps no tokens")
			}
			for _, e := range app.GetLogEntries() {
				a.NotContains(e.Message, "resumption tokens", e.Level)
			}
			sessions, err := store.ListSessions()
			a.NoError(err)
			if tc.incognito {
				a.Empty(sessions,
					"closing an incognito session must not store it")
			}
		})
	}
}
