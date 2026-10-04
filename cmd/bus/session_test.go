package main

import (
	"net"
	"sync/atomic"
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
				addr, "tcp", "", "", "", "", "", "", "", false, false,
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
