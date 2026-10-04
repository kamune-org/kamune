package kamune

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xtaci/kcp-go/v5"

	"github.com/kamune-org/kamune/internal/clock"
	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/storage"
)

func TestServerHandshakeDeadlineCoversExchange(t *testing.T) {
	a := require.New(t)
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	s := &Server{handshakeOpts: handshakeOpts{timeout: 50 * time.Millisecond}}
	done := make(chan error, 1)
	go func() {
		done <- s.serve(newConn(server))
	}()

	select {
	case err := <-done:
		a.Error(err)
	case <-time.After(time.Second):
		a.Fail("server exchange did not honor the handshake deadline")
	}
}

func TestServerClearsHandshakeDeadlineBeforeHandler(t *testing.T) {
	a := require.New(t)
	clientStore, cleanupClient := newTestStore(t)
	defer cleanupClient()
	serverStore, cleanupServer := newTestStore(t)
	defer cleanupServer()

	clientNet, serverNet := net.Pipe()
	clientConn := newConn(clientNet)
	serverConn := newConn(serverNet)
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	verifier := func(store *storage.Storage, peer *storage.Peer) error {
		return store.StorePeer(peer)
	}
	handlerErr := make(chan error, 1)
	server, err := NewServer(
		"",
		func(transport *Transport) error {
			time.Sleep(650 * time.Millisecond)
			_, err := transport.Send(Bytes([]byte("after deadline")), RouteExchangeMessages)
			handlerErr <- err
			return err
		},
		serverStore,
		verifier,
	)
	a.NoError(err)
	server.handshakeOpts.timeout = 500 * time.Millisecond

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.serve(serverConn)
	}()

	dialer, err := NewDialer(
		"",
		clientStore,
		verifier,
		DialWithFunc(func(string) (Conn, error) { return clientConn, nil }),
	)
	a.NoError(err)
	transport, err := dialer.Dial()
	a.NoError(err)

	message := Bytes(nil)
	_, err = transport.Receive(message)
	a.NoError(err)
	a.Equal([]byte("after deadline"), message.Value)
	a.NoError(<-handlerErr)
	a.NoError(<-serveErr)
}

func coldDial(
	t *testing.T, clientStore, serverStore *storage.Storage,
) string {
	t.Helper()
	a := require.New(t)
	verifier := func(store *storage.Storage, peer *storage.Peer) error {
		return store.StorePeer(peer)
	}

	clientNet, serverNet := net.Pipe()
	clientConn := newConn(clientNet)
	serverConn := newConn(serverNet)
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	serveErr := make(chan error, 1)
	server, err := NewServer(
		"",
		func(tr *Transport) error {
			_, err := tr.Send(Bytes([]byte("ok")), RouteExchangeMessages)
			return err
		},
		serverStore,
		verifier,
	)
	a.NoError(err)
	go func() {
		serveErr <- server.serve(serverConn)
	}()

	dialer, err := NewDialer(
		"",
		clientStore,
		verifier,
		DialWithFunc(func(string) (Conn, error) {
			return clientConn, nil
		}),
	)
	a.NoError(err)
	tr, err := dialer.Dial()
	a.NoError(err)
	msg := Bytes(nil)
	_, err = tr.Receive(msg)
	a.NoError(err)
	a.Equal([]byte("ok"), msg.Value)
	a.NoError(<-serveErr)
	return tr.SessionID()
}

func TestDialPersistsAndResumesSession(t *testing.T) {
	a := require.New(t)
	clientStore, cleanupClient := newTestStore(t)
	defer cleanupClient()
	serverStore, cleanupServer := newTestStore(t)
	defer cleanupServer()

	sessionID := coldDial(t, clientStore, serverStore)
	for _, store := range []*storage.Storage{clientStore, serverStore} {
		m, err := store.GetMeta(sessionID, storage.ResumptionTokensKey)
		a.NoError(err)
		a.Greater(len(m.Value()), 4)
		_, err = store.GetEstablishedAt(sessionID)
		a.NoError(err)
	}

	verifier := func(store *storage.Storage, peer *storage.Peer) error {
		return store.StorePeer(peer)
	}
	clientNet, serverNet := net.Pipe()
	clientConn := newConn(clientNet)
	serverConn := newConn(serverNet)
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	serveErr := make(chan error, 1)
	server, err := NewServer(
		"",
		func(tr *Transport) error {
			a.Equal(sessionID, tr.SessionID())
			_, err := tr.Send(Bytes([]byte("resumed")), RouteExchangeMessages)
			return err
		},
		serverStore,
		verifier,
	)
	a.NoError(err)
	go func() {
		serveErr <- server.serve(serverConn)
	}()

	dialer, err := NewDialer(
		"",
		clientStore,
		verifier,
		DialWithResume(sessionID),
		DialWithFunc(func(string) (Conn, error) {
			return clientConn, nil
		}),
	)
	a.NoError(err)
	tr, err := dialer.Dial()
	a.NoError(err)
	a.Equal(sessionID, tr.SessionID())
	msg := Bytes(nil)
	_, err = tr.Receive(msg)
	a.NoError(err)
	a.Equal([]byte("resumed"), msg.Value)
	a.NoError(<-serveErr)
}

func TestHandleResumeRejectsWithoutBurningToken(t *testing.T) {
	a := require.New(t)
	clientStore, cleanupClient := newTestStore(t)
	defer cleanupClient()
	serverStore, cleanupServer := newTestStore(t)
	defer cleanupServer()

	sessionID := coldDial(t, clientStore, serverStore)
	before, err := serverStore.GetMeta(sessionID, storage.ResumptionTokensKey)
	a.NoError(err)

	token, err := clientStore.PopList(sessionID, storage.ResumptionTokensKey)
	a.NoError(err)
	wrong, err := attest.New()
	a.NoError(err)

	clientNet, serverNet := net.Pipe()
	clientConn := newConn(clientNet)
	serverConn := newConn(serverNet)
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	verifier := func(store *storage.Storage, peer *storage.Peer) error {
		return store.StorePeer(peer)
	}
	server, err := NewServer(
		"", func(*Transport) error { return nil }, serverStore, verifier,
	)
	a.NoError(err)
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.serve(serverConn)
	}()

	ec, err := exchange.Initiate(clientConn)
	a.NoError(err)
	a.NoError(sendResumeRequest(ec, wrong, sessionID, token))
	accepted, _, err := receiveResumeAccept(ec, server.PublicKey())
	a.NoError(err)
	a.False(accepted)

	after, err := serverStore.GetMeta(sessionID, storage.ResumptionTokensKey)
	a.NoError(err)
	a.Equal(before.Value(), after.Value())
	a.Error(<-serveErr)
}

func TestHandleResumeRejectsWrongLengthToken(t *testing.T) {
	a := require.New(t)
	clientStore, cleanupClient := newTestStore(t)
	defer cleanupClient()
	serverStore, cleanupServer := newTestStore(t)
	defer cleanupServer()

	sessionID := coldDial(t, clientStore, serverStore)
	before, err := serverStore.GetMeta(sessionID, storage.ResumptionTokensKey)
	a.NoError(err)
	clientAt, err := clientStore.Attester()
	a.NoError(err)

	clientNet, serverNet := net.Pipe()
	clientConn := newConn(clientNet)
	serverConn := newConn(serverNet)
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	verifier := func(store *storage.Storage, peer *storage.Peer) error {
		return store.StorePeer(peer)
	}
	server, err := NewServer(
		"", func(*Transport) error { return nil }, serverStore, verifier,
	)
	a.NoError(err)
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.serve(serverConn)
	}()

	ec, err := exchange.Initiate(clientConn)
	a.NoError(err)
	a.NoError(sendResumeRequest(ec, clientAt, sessionID, []byte{1, 2, 3}))
	accepted, _, err := receiveResumeAccept(ec, server.PublicKey())
	a.NoError(err)
	a.False(accepted)

	after, err := serverStore.GetMeta(sessionID, storage.ResumptionTokensKey)
	a.NoError(err)
	a.Equal(before.Value(), after.Value())
	a.Error(<-serveErr)
}

type metaConn struct {
	Conn
	v any
}

func (m metaConn) AcceptedMeta() any { return m.v }

func TestAcceptedMeta_ReachesHandler(t *testing.T) {
	a := require.New(t)
	clientStore, cleanupClient := newTestStore(t)
	defer cleanupClient()
	serverStore, cleanupServer := newTestStore(t)
	defer cleanupServer()

	label := "tok"
	clientNet, serverNet := net.Pipe()
	clientConn := newConn(clientNet)
	serverConn := metaConn{Conn: newConn(serverNet), v: &label}
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	got := make(chan any, 1)
	verifier := func(store *storage.Storage, peer *storage.Peer) error {
		return store.StorePeer(peer)
	}
	server, err := NewServer(
		"",
		func(tr *Transport) error {
			got <- tr.AcceptedMeta()
			return nil
		},
		serverStore,
		verifier,
	)
	a.NoError(err)
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.serve(serverConn)
	}()

	dialer, err := NewDialer(
		"",
		clientStore,
		verifier,
		DialWithFunc(func(string) (Conn, error) { return clientConn, nil }),
	)
	a.NoError(err)
	tr, err := dialer.Dial()
	a.NoError(err)
	t.Cleanup(func() { _ = tr.Close() })

	a.Equal(&label, <-got)
	a.NoError(<-serveErr)
}

func TestWithoutPersistenceLeavesNoSessionRecord(t *testing.T) {
	cases := []struct {
		name       string
		serverOpts []ServerOptions
		dialOpts   []DialOption
		wantServer int
		wantClient int
	}{
		{
			name:       "default persists both sides",
			wantServer: 1,
			wantClient: 1,
		},
		{
			name:       "server without persistence",
			serverOpts: []ServerOptions{ServeWithoutPersistence()},
			wantClient: 1,
		},
		{
			name:       "dialer without persistence",
			dialOpts:   []DialOption{DialWithoutPersistence()},
			wantServer: 1,
		},
		{
			name:       "both without persistence",
			serverOpts: []ServerOptions{ServeWithoutPersistence()},
			dialOpts:   []DialOption{DialWithoutPersistence()},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			clientStore, cleanupClient := newTestStore(t)
			defer cleanupClient()
			serverStore, cleanupServer := newTestStore(t)
			defer cleanupServer()

			clientNet, serverNet := net.Pipe()
			clientConn := newConn(clientNet)
			serverConn := newConn(serverNet)
			t.Cleanup(func() {
				_ = clientConn.Close()
				_ = serverConn.Close()
			})

			verifier := func(*storage.Storage, *storage.Peer) error {
				return nil
			}
			server, err := NewServer(
				"",
				func(tr *Transport) error {
					_, err := tr.Receive(Bytes(nil))
					if errors.Is(err, ErrPeerDisconnected) {
						return nil
					}
					return err
				},
				serverStore,
				verifier,
				tc.serverOpts...,
			)
			a.NoError(err)
			serveErr := make(chan error, 1)
			go func() {
				serveErr <- server.serve(serverConn)
			}()

			dialer, err := NewDialer("", clientStore, verifier, append(
				tc.dialOpts,
				DialWithFunc(func(string) (Conn, error) {
					return clientConn, nil
				}),
			)...)
			a.NoError(err)
			tr, err := dialer.Dial()
			a.NoError(err)
			a.NoError(tr.Close())
			a.NoError(<-serveErr)

			sessions, err := serverStore.ListSessions()
			a.NoError(err)
			a.Len(sessions, tc.wantServer, "server sessions")
			sessions, err = clientStore.ListSessions()
			a.NoError(err)
			a.Len(sessions, tc.wantClient, "client sessions")
		})
	}
}

func TestWithoutPersistenceResumedSessionLosesTokensOnClose(t *testing.T) {
	cases := []struct {
		name       string
		serverOpts []ServerOptions
		dialOpts   []DialOption
	}{
		{
			name:       "server without persistence",
			serverOpts: []ServerOptions{ServeWithoutPersistence()},
		},
		{
			name:     "dialer without persistence",
			dialOpts: []DialOption{DialWithoutPersistence()},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			clientStore, cleanupClient := newTestStore(t)
			defer cleanupClient()
			serverStore, cleanupServer := newTestStore(t)
			defer cleanupServer()
			sessionID := coldDial(t, clientStore, serverStore)

			clientNet, serverNet := net.Pipe()
			clientConn := newConn(clientNet)
			serverConn := newConn(serverNet)
			t.Cleanup(func() {
				_ = clientConn.Close()
				_ = serverConn.Close()
			})

			verifier := func(*storage.Storage, *storage.Peer) error {
				return nil
			}
			server, err := NewServer(
				"",
				func(tr *Transport) error {
					_, err := tr.Receive(Bytes(nil))
					if errors.Is(err, ErrPeerDisconnected) {
						return nil
					}
					return err
				},
				serverStore,
				verifier,
				tc.serverOpts...,
			)
			a.NoError(err)
			serveErr := make(chan error, 1)
			go func() {
				serveErr <- server.serve(serverConn)
			}()

			dialer, err := NewDialer("", clientStore, verifier, append(
				tc.dialOpts,
				DialWithResume(sessionID),
				DialWithFunc(func(string) (Conn, error) {
					return clientConn, nil
				}),
			)...)
			a.NoError(err)
			tr, err := dialer.Dial()
			a.NoError(err)
			a.Equal(sessionID, tr.SessionID())
			a.NoError(tr.Close())
			a.NoError(<-serveErr)

			stores := map[string]*storage.Storage{
				"server": serverStore,
				"client": clientStore,
			}
			for side, store := range stores {
				_, err := store.PopList(sessionID, storage.ResumptionTokensKey)
				a.ErrorIs(err, storage.ErrNotFound, "%s tokens", side)
			}
		})
	}
}

func TestNilStorageIsAnError(t *testing.T) {
	verifier := func(*storage.Storage, *storage.Peer) error { return nil }
	cases := []struct {
		build func() error
		name  string
	}{
		{
			name: "server",
			build: func() error {
				_, err := NewServer(
					"127.0.0.1:0",
					func(*Transport) error { return nil },
					nil,
					verifier,
					ServeWithTCP(),
				)
				return err
			},
		},
		{
			name: "dialer",
			build: func() error {
				_, err := NewDialer("127.0.0.1:0", nil, verifier)
				return err
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			var err error
			a.NotPanics(func() { err = tc.build() })
			a.ErrorIs(err, ErrMissingStorage)
		})
	}
}

// testListener is a Listener driven by the test. Accept first returns errs
// in order, then hands out the conns sent on conns until Close, after which
// it returns closeErr. Each Accept call is reported on calls.
type testListener struct {
	closeErr error
	conns    chan Conn
	calls    chan time.Time
	done     chan struct{}
	errs     []error
	once     sync.Once
	mu       sync.Mutex
}

func newTestListener(closeErr error, errs ...error) *testListener {
	return &testListener{
		closeErr: closeErr,
		conns:    make(chan Conn),
		calls:    make(chan time.Time, 64),
		done:     make(chan struct{}),
		errs:     errs,
	}
}

func (l *testListener) Accept() (Conn, error) {
	select {
	case l.calls <- time.Now():
	default:
	}
	l.mu.Lock()
	if len(l.errs) > 0 {
		err := l.errs[0]
		l.errs = l.errs[1:]
		l.mu.Unlock()
		return nil, err
	}
	l.mu.Unlock()
	select {
	case cn := <-l.conns:
		return cn, nil
	case <-l.done:
		return nil, l.closeErr
	}
}

func (l *testListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

// sourceConn reports a chosen remote address and records when it is closed.
type sourceConn struct {
	Conn
	addr   net.Addr
	closed chan struct{}
	once   sync.Once
}

func newSourceConn(cn Conn, addr string) *sourceConn {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		panic(err)
	}
	return &sourceConn{Conn: cn, addr: tcpAddr, closed: make(chan struct{})}
}

// newUDPSourceConn is newSourceConn for a connection over UDP, whose source
// address can be forged.
func newUDPSourceConn(cn Conn, addr string) *sourceConn {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		panic(err)
	}
	return &sourceConn{Conn: cn, addr: udpAddr, closed: make(chan struct{})}
}

func (c *sourceConn) RemoteAddr() net.Addr { return c.addr }

func (c *sourceConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func (c *sourceConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

// startTestServer runs ListenAndServe on l and returns the server and a
// channel with its result.
func startTestServer(
	t *testing.T, l Listener, opts ...ServerOptions,
) (*Server, chan error) {
	t.Helper()
	a := require.New(t)
	store, cleanup := newTestStore(t)
	t.Cleanup(cleanup)
	server, err := NewServer(
		"",
		func(*Transport) error { return nil },
		store,
		func(*storage.Storage, *storage.Peer) error { return nil },
		append(opts, ServeWithListener(l))...,
	)
	a.NoError(err)
	result := make(chan error, 1)
	go func() { result <- server.ListenAndServe() }()
	t.Cleanup(func() { _ = server.Close() })
	return server, result
}

func TestListenAndServeBacksOffOnAcceptErrors(t *testing.T) {
	a := require.New(t)
	errTemp := errors.New("accept4: too many open files")
	l := newTestListener(net.ErrClosed, errTemp, errTemp, errTemp, errTemp)
	server, result := startTestServer(t, l)

	var calls []time.Time
	for range 5 {
		select {
		case c := <-l.calls:
			calls = append(calls, c)
		case <-time.After(10 * time.Second):
			a.FailNow("accept was not called again")
		}
	}
	want := minAcceptDelay
	for i := 1; i < len(calls); i++ {
		a.GreaterOrEqual(calls[i].Sub(calls[i-1]), want, "wait %d", i)
		want *= 2
	}

	a.NoError(server.Close())
	select {
	case err := <-result:
		a.NoError(err)
	case <-time.After(10 * time.Second):
		a.FailNow("ListenAndServe did not return after Close")
	}
}

func TestListenAndServeReturnsOnCloseWhateverAcceptReturns(t *testing.T) {
	cases := []struct {
		closeErr error
		name     string
	}{
		{name: "net.ErrClosed", closeErr: net.ErrClosed},
		{
			name:     "kcp closed pipe",
			closeErr: fmt.Errorf("accept: %w", io.ErrClosedPipe),
		},
		{name: "other error", closeErr: errors.New("listener gone")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			l := newTestListener(tc.closeErr)
			server, result := startTestServer(t, l)
			<-l.calls

			a.NoError(server.Close())
			select {
			case err := <-result:
				a.NoError(err)
			case <-time.After(10 * time.Second):
				a.FailNow("ListenAndServe did not return after Close")
			}
			a.Empty(l.calls, "Accept called again after Close")
		})
	}
}

// sendConn hands cn to the server through l, failing the test if the server
// does not accept it in time.
func sendConn(t *testing.T, l *testListener, cn Conn) {
	t.Helper()
	select {
	case l.conns <- cn:
	case <-time.After(10 * time.Second):
		require.New(t).FailNow("the server stopped accepting")
	}
}

func TestListenAndServeDropsWaitingConnAtCap(t *testing.T) {
	cases := []struct {
		name string
		// addrs are the sources of the connections in the order they are
		// accepted. All of them wait; the last one arrives at the cap.
		addrs []string
		max   int
		// drop is the index in addrs of the connection that is closed.
		drop int
	}{
		{
			name:  "one source",
			max:   1,
			addrs: []string{"10.0.0.1:1", "10.0.0.1:2"},
			drop:  0,
		},
		{
			name: "oldest of the busiest network",
			max:  3,
			addrs: []string{
				"10.0.1.1:1", "10.0.2.1:1", "10.0.2.2:1", "10.0.3.1:1",
			},
			drop: 1,
		},
		{
			name: "new connection counts for its network",
			max:  3,
			addrs: []string{
				"10.0.1.1:1", "10.0.2.1:1", "10.0.3.1:1", "10.0.3.2:1",
			},
			drop: 2,
		},
		{
			name: "ipv6 /64s of one /48 are one network",
			max:  2,
			addrs: []string{
				"[2001:db8:1:1::1]:1",
				"[2001:db8:1:2::1]:1",
				"[2001:db8:2::1]:1",
			},
			drop: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			l := newTestListener(net.ErrClosed)
			// Keep the idle connections waiting for the whole test.
			startTestServer(
				t, l,
				ServeWithMaxPendingHandshakes(tc.max),
				ServeWithIntroTimeout(time.Hour),
			)

			conns := make([]*sourceConn, len(tc.addrs))
			for i, addr := range tc.addrs {
				clientNet, serverNet := net.Pipe()
				t.Cleanup(func() {
					_ = clientNet.Close()
					_ = serverNet.Close()
				})
				conns[i] = newSourceConn(newConn(serverNet), addr)
				sendConn(t, l, conns[i])
			}
			// The server calls Accept once more after it has dealt with
			// the last connection, so by then it has closed the one it
			// dropped.
			for range len(conns) + 1 {
				select {
				case <-l.calls:
				case <-time.After(10 * time.Second):
					a.FailNow("accept was not called again")
				}
			}
			for i, c := range conns {
				a.Equal(
					i == tc.drop, c.isClosed(),
					"connection %d from %s", i, tc.addrs[i],
				)
			}
		})
	}
}

func TestListenAndServeCapsPendingPerSource(t *testing.T) {
	a := require.New(t)
	l := newTestListener(net.ErrClosed)
	startTestServer(t, l, ServeWithMaxPendingPerSource(1))

	pending := func(addr string) *sourceConn {
		clientNet, serverNet := net.Pipe()
		t.Cleanup(func() {
			_ = clientNet.Close()
			_ = serverNet.Close()
		})
		return newSourceConn(newConn(serverNet), addr)
	}
	first := pending("10.0.0.1:4000")
	second := pending("10.0.0.1:4001")
	other := pending("10.0.0.2:4000")

	l.conns <- first
	l.conns <- second
	select {
	case <-second.closed:
	case <-time.After(10 * time.Second):
		a.FailNow("second connection from the same source was not closed")
	}
	l.conns <- other
	// Accept handed out the three connections in its first three calls.
	// The fourth call comes after the server has dealt with other.
	for range 4 {
		select {
		case <-l.calls:
		case <-time.After(10 * time.Second):
			a.FailNow("accept was not called again")
		}
	}
	a.False(first.isClosed(), "first connection was closed")
	a.False(other.isClosed(), "connection from another source was closed")
}

// stringAddr is a net.Addr with a fixed string form.
type stringAddr string

func (stringAddr) Network() string  { return "test" }
func (a stringAddr) String() string { return string(a) }

func TestSourceKey(t *testing.T) {
	cases := []struct {
		name    string
		addr    string
		source  string
		network string
	}{
		{
			name:    "ipv4",
			addr:    "192.0.2.7:4000",
			source:  "192.0.2.7",
			network: "192.0.2.0/24",
		},
		{
			name:    "ipv4-mapped ipv6",
			addr:    "[::ffff:192.0.2.7]:4000",
			source:  "192.0.2.7",
			network: "192.0.2.0/24",
		},
		{
			name:    "ipv6",
			addr:    "[2001:db8:1:2:aaaa:bbbb:cccc:dddd]:4000",
			source:  "2001:db8:1:2::/64",
			network: "2001:db8:1::/48",
		},
		{
			name:    "ipv6 with zone",
			addr:    "[fe80::1%eth0]:4000",
			source:  "fe80::/64",
			network: "fe80::/48",
		},
		{
			name:    "ipv6 without port",
			addr:    "2001:db8::1",
			source:  "2001:db8::/64",
			network: "2001:db8::/48",
		},
		{
			name:    "host name",
			addr:    "example.com:80",
			source:  "example.com",
			network: "example.com",
		},
		{
			name:    "not an ip address",
			addr:    "pipe",
			source:  "pipe",
			network: "pipe",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			a.Equal(tc.source, sourceKey(stringAddr(tc.addr)))
			a.Equal(tc.network, networkKey(stringAddr(tc.addr)))
		})
	}
}

func TestListenAndServeLimitsPerSourceByDefault(t *testing.T) {
	a := require.New(t)
	l := newTestListener(net.ErrClosed)
	// Keep the idle connections pending for the whole test.
	startTestServer(t, l, ServeWithIntroTimeout(time.Hour))

	// All addresses are in one /64, so they count as one source.
	conns := make([]*sourceConn, defaultMaxPendingPerSource+1)
	for i := range conns {
		clientNet, serverNet := net.Pipe()
		t.Cleanup(func() {
			_ = clientNet.Close()
			_ = serverNet.Close()
		})
		addr := fmt.Sprintf("[2001:db8::%x]:4000", i+1)
		conns[i] = newSourceConn(newConn(serverNet), addr)
		l.conns <- conns[i]
	}

	over := conns[len(conns)-1]
	select {
	case <-over.closed:
	case <-time.After(10 * time.Second):
		a.FailNow("connection over the default per-source cap was kept")
	}
	for i, c := range conns[:len(conns)-1] {
		a.False(c.isClosed(), "connection %d was closed", i)
	}
}

func TestIdleConnIsClosedAfterIntroTimeout(t *testing.T) {
	a := require.New(t)
	l := newTestListener(net.ErrClosed)
	startTestServer(t, l, ServeWithIntroTimeout(time.Second))

	clientNet, serverNet := net.Pipe()
	t.Cleanup(func() {
		_ = clientNet.Close()
		_ = serverNet.Close()
	})
	sendConn(t, l, newConn(serverNet))

	// The handshake timeout is 30 s, so a close within 10 s comes from the
	// intro timeout. SetReadDeadline fails on a pipe whose other end is
	// closed already, and then Read reports EOF.
	_ = clientNet.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, err := clientNet.Read(make([]byte, 1))
	a.ErrorIs(err, io.EOF)
}

func TestIdleTCPConnsFromOneHostDoNotBlockDialer(t *testing.T) {
	a := require.New(t)
	// The idle connections come from a second loopback address, so that
	// they and the dialer are different sources.
	attacker := &net.Dialer{
		LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2)},
		Timeout:   10 * time.Second,
	}
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	a.NoError(err)
	c, err := attacker.Dial("tcp", probe.Addr().String())
	_ = probe.Close()
	if err != nil {
		t.Skipf("cannot dial from 127.0.0.2: %v", err)
	}
	_ = c.Close()

	serverStore, cleanupServer := newTestStore(t)
	t.Cleanup(cleanupServer)
	clientStore, cleanupClient := newTestStore(t)
	t.Cleanup(cleanupClient)
	verifier := func(*storage.Storage, *storage.Peer) error { return nil }
	server, err := NewServer(
		"127.0.0.1:0",
		func(*Transport) error { return nil },
		serverStore,
		verifier,
		ServeWithTCP(),
	)
	a.NoError(err)
	addr := server.listener.(*tcpListener).Addr().String()
	go func() { _ = server.ListenAndServe() }()
	t.Cleanup(func() { _ = server.Close() })

	// As many idle connections as may wait for their introduction by
	// default.
	for range defaultMaxPendingHandshakes {
		c, err := attacker.Dial("tcp", addr)
		a.NoError(err)
		t.Cleanup(func() { _ = c.Close() })
	}

	dialer, err := NewDialer(addr, clientStore, verifier, DialWithTCP())
	a.NoError(err)
	dialed := make(chan error, 1)
	go func() {
		tr, err := dialer.Dial()
		if err == nil {
			_ = tr.CloseAbort()
		}
		dialed <- err
	}()
	// Before the per-source cap and the intro timeout, the dial waited
	// for the 30 s handshake timeout and failed.
	select {
	case err := <-dialed:
		a.NoError(err)
	case <-time.After(defaultIntroTimeout + 10*time.Second):
		a.FailNow("idle connections from one host blocked the dialer")
	}
}

func TestIdleTCPConnsFromManyHostsDoNotBlockDialer(t *testing.T) {
	const (
		hosts = 64
		// Each host keeps as many sockets as the per-source cap allows,
		// so together they hold far more than the waiting connections
		// the server allows.
		perHost = defaultMaxPendingPerSource
		// reconnectPause is how long an idle socket that the server
		// closed waits before it connects again.
		reconnectPause = 200 * time.Millisecond
	)
	a := require.New(t)
	hostDialer := func(i int) *net.Dialer {
		return &net.Dialer{
			LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 1, byte(i+1))},
			Timeout:   10 * time.Second,
		}
	}
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	a.NoError(err)
	c, err := hostDialer(hosts-1).Dial("tcp", probe.Addr().String())
	_ = probe.Close()
	if err != nil {
		t.Skipf("cannot dial from 127.0.1.%d: %v", hosts, err)
	}
	_ = c.Close()

	serverStore, cleanupServer := newTestStore(t)
	t.Cleanup(cleanupServer)
	clientStore, cleanupClient := newTestStore(t)
	t.Cleanup(cleanupClient)
	verifier := func(*storage.Storage, *storage.Peer) error { return nil }
	server, err := NewServer(
		"127.0.0.1:0",
		func(*Transport) error { return nil },
		serverStore,
		verifier,
		ServeWithTCP(),
	)
	a.NoError(err)
	addr := server.listener.(*tcpListener).Addr().String()
	go func() { _ = server.ListenAndServe() }()
	t.Cleanup(func() { _ = server.Close() })

	// Every socket sends nothing and connects again whenever the server
	// closes it, as an attacker holding its places would.
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})
	connected := make(chan struct{}, hosts*perHost)
	for i := range hosts {
		d := hostDialer(i)
		for range perHost {
			wg.Go(func() {
				first := true
				for ctx.Err() == nil {
					c, err := d.DialContext(ctx, "tcp", addr)
					if err == nil {
						if first {
							connected <- struct{}{}
							first = false
						}
						stop := context.AfterFunc(ctx, func() {
							_ = c.Close()
						})
						_, _ = c.Read(make([]byte, 1))
						stop()
						_ = c.Close()
					}
					select {
					case <-ctx.Done():
					case <-time.After(reconnectPause):
					}
				}
			})
		}
	}
	for range hosts * perHost {
		select {
		case <-connected:
		case <-time.After(30 * time.Second):
			a.FailNow("the idle sockets did not connect")
		}
	}

	dialer, err := NewDialer(addr, clientStore, verifier, DialWithTCP())
	a.NoError(err)
	dialed := make(chan error, 1)
	go func() {
		tr, err := dialer.Dial()
		if err == nil {
			_ = tr.CloseAbort()
		}
		dialed <- err
	}()
	// When the server stopped accepting at the cap, the dialer queued in
	// the listen backlog behind the idle sockets and failed after 30 s.
	select {
	case err := <-dialed:
		a.NoError(err)
	case <-time.After(20 * time.Second):
		a.FailNow("idle connections from many hosts blocked the dialer")
	}
}

// gatedConn holds the first ReadBytes until gate is closed, as a slow link
// holds the reply the dialer waits for.
type gatedConn struct {
	Conn
	gate <-chan struct{}
}

func (c *gatedConn) ReadBytes() ([]byte, error) {
	<-c.gate
	return c.Conn.ReadBytes()
}

// newGate returns a gate for gatedConn and a func that opens it, which may
// be called more than once. The gate is opened when the test ends.
func newGate(t *testing.T) (<-chan struct{}, func()) {
	gate := make(chan struct{})
	var once sync.Once
	open := func() { once.Do(func() { close(gate) }) }
	t.Cleanup(open)
	return gate, open
}

// dialAsync runs dialer.Dial in a goroutine and returns its result.
func dialAsync(dialer *Dialer) <-chan error {
	dialed := make(chan error, 1)
	go func() {
		tr, err := dialer.Dial()
		if err == nil {
			_ = tr.CloseAbort()
		}
		dialed <- err
	}()
	return dialed
}

func TestIdleConnsFromOneNetworkDoNotDropDialer(t *testing.T) {
	a := require.New(t)
	clientStore, cleanupClient := newTestStore(t)
	t.Cleanup(cleanupClient)
	verifier := func(*storage.Storage, *storage.Peer) error { return nil }
	l := newTestListener(net.ErrClosed)
	// Keep the idle connections waiting for the whole test.
	startTestServer(t, l, ServeWithIntroTimeout(time.Hour))

	// Every idle connection comes from its own /64, so each is a source
	// with nothing else waiting, but all of them are in one /48.
	next := 0
	idle := func() {
		clientNet, serverNet := net.Pipe()
		t.Cleanup(func() {
			_ = clientNet.Close()
			_ = serverNet.Close()
		})
		next++
		addr := fmt.Sprintf("[2001:db8:1:%x::1]:4000", next)
		sendConn(t, l, newSourceConn(newConn(serverNet), addr))
	}
	for range defaultMaxPendingHandshakes {
		idle()
	}

	// The dialer does not get the server's reply until the gate opens, as
	// on a slow link.
	gate, openGate := newGate(t)
	clientNet, serverNet := net.Pipe()
	clientConn := &gatedConn{Conn: newConn(clientNet), gate: gate}
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverNet.Close()
	})
	dialerConn := newSourceConn(newConn(serverNet), "[2001:db8:2::1]:4000")
	sendConn(t, l, dialerConn)
	dialer, err := NewDialer(
		"", clientStore, verifier,
		DialWithFunc(func(string) (Conn, error) { return clientConn, nil }),
	)
	a.NoError(err)
	dialed := dialAsync(dialer)

	// When the oldest waiting connection was dropped whenever every source
	// had one waiting, the dialer was dropped after the next 256.
	for range 2 * defaultMaxPendingHandshakes {
		idle()
	}
	a.False(dialerConn.isClosed(), "the dialer was dropped")

	openGate()
	select {
	case err := <-dialed:
		a.NoError(err)
	case <-time.After(30 * time.Second):
		a.FailNow("the dial did not complete")
	}
}

func TestTiedNetworksLoseConnsAtRandom(t *testing.T) {
	a := require.New(t)
	addrs := []string{"10.0.1.1:1", "10.0.2.1:1"}
	dropped := make(map[string]int)
	store, cleanup := newTestStore(t)
	t.Cleanup(cleanup)
	for range 200 {
		server, err := NewServer(
			"",
			func(*Transport) error { return nil },
			store,
			func(*storage.Storage, *storage.Peer) error { return nil },
			ServeWithListener(newTestListener(net.ErrClosed)),
			ServeWithMaxPendingHandshakes(len(addrs)),
		)
		a.NoError(err)
		for _, addr := range addrs {
			_, victim, ok := server.admit(newSourceConn(nil, addr))
			a.True(ok)
			a.Nil(victim)
		}
		// Every network has one connection waiting, the new one's
		// included, so either waiting connection may go.
		_, victim, ok := server.admit(newSourceConn(nil, "10.0.3.1:1"))
		a.True(ok)
		a.NotNil(victim)
		dropped[victim.(*sourceConn).addr.String()]++
	}
	for _, addr := range addrs {
		a.Positive(dropped[addr], "%s was never dropped", addr)
	}
}

func TestPendingCapsByTransport(t *testing.T) {
	cases := []struct {
		newConn func(cn Conn, addr string) *sourceConn
		name    string
		// atAccept is whether the per-source cap counts a connection from
		// the moment it is accepted, rather than from the introduction.
		atAccept bool
	}{
		{name: "tcp", newConn: newSourceConn, atAccept: true},
		{name: "udp", newConn: newUDPSourceConn},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			store, cleanup := newTestStore(t)
			t.Cleanup(cleanup)
			newServer := func() *Server {
				server, err := NewServer(
					"",
					func(*Transport) error { return nil },
					store,
					func(*storage.Storage, *storage.Peer) error { return nil },
					ServeWithListener(newTestListener(net.ErrClosed)),
				)
				a.NoError(err)
				return server
			}

			// One source, one more connection than the per-source cap.
			server := newServer()
			var conns []*pendingConn
			for i := range defaultMaxPendingPerSource + 1 {
				addr := fmt.Sprintf("10.0.0.1:%d", i+1)
				p, _, ok := server.admit(tc.newConn(nil, addr))
				last := i == defaultMaxPendingPerSource
				a.Equal(!(last && tc.atAccept), ok, "admit %d", i)
				if ok {
					conns = append(conns, p)
				}
			}
			if !tc.atAccept {
				for i, p := range conns {
					err := server.introduced(p)
					if i < defaultMaxPendingPerSource {
						a.NoError(err, "introduction %d", i)
					} else {
						a.Error(err, "introduction over the cap")
					}
				}
			}
			// The end of a handshake frees a place for the source.
			server.endHandshake(conns[0])
			p, _, ok := server.admit(tc.newConn(nil, "10.0.0.1:9999"))
			a.True(ok)
			a.NoError(server.introduced(p))

			// Each connection from a network of its own: the cap on
			// waiting connections applies whatever the transport.
			server = newServer()
			for i := range defaultMaxPendingHandshakes {
				addr := fmt.Sprintf("10.1.%d.1:1", i)
				_, victim, ok := server.admit(tc.newConn(nil, addr))
				a.True(ok, "connection %d", i)
				a.Nil(victim, "connection %d", i)
			}
			_, victim, ok := server.admit(tc.newConn(nil, "10.2.0.1:1"))
			a.True(ok)
			a.NotNil(victim, "connection over the cap made no room")
		})
	}
}

// kcpPush returns a KCP segment that pushes one byte on conversation conv.
// It is all a kcp-go listener needs to accept a new session from the
// datagram's source address.
func kcpPush(conv uint32) []byte {
	const cmdPush = 81
	b := make([]byte, 25)
	binary.LittleEndian.PutUint32(b[0:], conv)
	b[4] = cmdPush
	binary.LittleEndian.PutUint16(b[6:], 32) // window
	binary.LittleEndian.PutUint32(b[20:], 1) // payload length
	return b
}

// acceptCalls is a Listener that reports each Accept call on calls.
type acceptCalls struct {
	Listener
	calls chan struct{}
}

func (l *acceptCalls) Accept() (Conn, error) {
	select {
	case l.calls <- struct{}{}:
	default:
	}
	return l.Listener.Accept()
}

func TestKCPFloodFromManySourcesDoesNotDropDialer(t *testing.T) {
	const sources = defaultMaxPendingHandshakes + 64
	a := require.New(t)
	// Each idle session comes from an address of its own, as a sender
	// that forges its source address would make them. The addresses lie
	// in two /24 networks, as in a flood from one site, so the server
	// makes room by dropping idle sessions rather than the dialer's.
	sourceIP := func(i int) net.IP {
		return net.IPv4(127, 1, byte(i/250), byte(i%250+1))
	}
	probe, err := net.ListenUDP(
		"udp4", &net.UDPAddr{IP: sourceIP(sources - 1)},
	)
	if err != nil {
		t.Skipf("cannot bind %s: %v", sourceIP(sources-1), err)
	}
	_ = probe.Close()

	serverStore, cleanupServer := newTestStore(t)
	t.Cleanup(cleanupServer)
	clientStore, cleanupClient := newTestStore(t)
	t.Cleanup(cleanupClient)
	verifier := func(*storage.Storage, *storage.Peer) error { return nil }
	kl, err := kcp.Listen("127.0.0.1:0")
	a.NoError(err)
	addr := kl.Addr().String()
	l := &acceptCalls{
		Listener: &udpListener{Listener: kl},
		calls:    make(chan struct{}, 1),
	}
	server, err := NewServer(
		"",
		func(*Transport) error { return nil },
		serverStore,
		verifier,
		ServeWithListener(l),
		// Keep the idle sessions for the whole test.
		ServeWithIntroTimeout(time.Hour),
	)
	a.NoError(err)
	go func() { _ = server.ListenAndServe() }()
	t.Cleanup(func() { _ = server.Close() })
	waitAccept := func() bool {
		select {
		case <-l.calls:
			return true
		case <-time.After(time.Second):
			return false
		}
	}
	a.True(waitAccept(), "the server did not call Accept")

	// The dialer does not get the server's reply until the gate opens, as
	// on a slow link.
	gate, openGate := newGate(t)
	dialer, err := NewDialer(
		addr, clientStore, verifier,
		DialWithFunc(func(addr string) (Conn, error) {
			c, err := kcp.Dial(addr)
			if err != nil {
				return nil, err
			}
			return &gatedConn{Conn: newConn(c), gate: gate}, nil
		}),
	)
	a.NoError(err)
	dialed := dialAsync(dialer)
	// The server calls Accept again once it has taken the dialer's
	// session.
	accepted := false
	for range 10 {
		if accepted = waitAccept(); accepted {
			break
		}
	}
	a.True(accepted, "the server did not accept the dialer")

	// When every source had one session waiting, the oldest was dropped
	// for each new one, so the dialer was dropped after the next 256.
	for i := range sources {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: sourceIP(i)})
		a.NoError(err)
		t.Cleanup(func() { _ = c.Close() })
		to, err := net.ResolveUDPAddr("udp4", addr)
		a.NoError(err)
		// Send again in case the datagram was lost.
		accepted = false
		for range 10 {
			_, err = c.WriteToUDP(kcpPush(uint32(i+1)), to)
			a.NoError(err)
			if accepted = waitAccept(); accepted {
				break
			}
		}
		a.True(accepted, "the server did not accept session %d", i)
	}

	openGate()
	select {
	case err := <-dialed:
		a.NoError(err)
	case <-time.After(30 * time.Second):
		a.FailNow("the dial did not complete")
	}
}

func TestIntroducedConnIsNotDropped(t *testing.T) {
	a := require.New(t)
	clientStore, cleanupClient := newTestStore(t)
	t.Cleanup(cleanupClient)
	serverStore, cleanupServer := newTestStore(t)
	t.Cleanup(cleanupServer)

	verifying := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseVerifier := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseVerifier)
	l := newTestListener(net.ErrClosed)
	server, err := NewServer(
		"",
		func(*Transport) error { return nil },
		serverStore,
		func(*storage.Storage, *storage.Peer) error {
			close(verifying)
			<-release
			return nil
		},
		ServeWithListener(l),
		ServeWithMaxPendingHandshakes(1),
		ServeWithIntroTimeout(time.Hour),
	)
	a.NoError(err)
	go func() { _ = server.ListenAndServe() }()
	t.Cleanup(func() { _ = server.Close() })

	clientNet, serverNet := net.Pipe()
	clientConn := newConn(clientNet)
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverNet.Close()
	})
	dialerConn := newSourceConn(newConn(serverNet), "10.0.0.1:1")
	sendConn(t, l, dialerConn)
	dialer, err := NewDialer(
		"",
		clientStore,
		func(*storage.Storage, *storage.Peer) error { return nil },
		DialWithFunc(func(string) (Conn, error) { return clientConn, nil }),
	)
	a.NoError(err)
	dialed := make(chan error, 1)
	go func() {
		tr, err := dialer.Dial()
		if err == nil {
			_ = tr.CloseAbort()
		}
		dialed <- err
	}()
	select {
	case <-verifying:
	case <-time.After(10 * time.Second):
		a.FailNow("the server verifier did not run")
	}

	// While the server's user verifies the dialer, two idle connections
	// arrive. The first takes the only waiting place, and the second takes
	// it from the first; the dialer, which has introduced itself, does not
	// count and is not dropped.
	idle := make([]*sourceConn, 2)
	for i := range idle {
		clientNet, serverNet := net.Pipe()
		t.Cleanup(func() {
			_ = clientNet.Close()
			_ = serverNet.Close()
		})
		addr := fmt.Sprintf("10.0.0.2:%d", i+1)
		idle[i] = newSourceConn(newConn(serverNet), addr)
		sendConn(t, l, idle[i])
	}
	select {
	case <-idle[0].closed:
	case <-time.After(10 * time.Second):
		a.FailNow("the older idle connection was not dropped")
	}
	a.False(idle[1].isClosed(), "the newer idle connection was dropped")
	a.False(dialerConn.isClosed(), "the introduced connection was dropped")

	releaseVerifier()
	select {
	case err := <-dialed:
		a.NoError(err)
	case <-time.After(10 * time.Second):
		a.FailNow("the dial did not complete")
	}
}

// logRecorder is a slog.Handler that keeps every record.
type logRecorder struct {
	records []slog.Record
	mu      sync.Mutex
}

func (*logRecorder) Enabled(context.Context, slog.Level) bool { return true }

func (h *logRecorder) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}

func (h *logRecorder) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *logRecorder) WithGroup(string) slog.Handler      { return h }

// levels returns the levels of the records with message msg.
func (h *logRecorder) levels(msg string) []slog.Level {
	h.mu.Lock()
	defer h.mu.Unlock()
	var levels []slog.Level
	for _, r := range h.records {
		if r.Message == msg {
			levels = append(levels, r.Level)
		}
	}
	return levels
}

func TestServeConnLogLevel(t *testing.T) {
	accept := func(*storage.Storage, *storage.Peer) error { return nil }
	reject := func(*storage.Storage, *storage.Peer) error {
		return ErrVerificationFailed
	}
	cases := []struct {
		verifier RemoteVerifier
		name     string
		msg      string
		level    slog.Level
		// dial is whether a dialer introduces itself; otherwise the
		// connection is closed before the exchange.
		dial bool
	}{
		{
			name:     "closed before the introduction",
			verifier: accept,
			msg:      "serve conn before introduction",
			level:    slog.LevelDebug,
		},
		{
			name:     "rejected after the introduction",
			verifier: reject,
			dial:     true,
			msg:      "serve conn",
			level:    slog.LevelError,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			rec := &logRecorder{}
			prev := slog.Default()
			slog.SetDefault(slog.New(rec))
			t.Cleanup(func() { slog.SetDefault(prev) })

			serverStore, cleanupServer := newTestStore(t)
			t.Cleanup(cleanupServer)
			l := newTestListener(net.ErrClosed)
			server, err := NewServer(
				"",
				func(*Transport) error { return nil },
				serverStore,
				tc.verifier,
				ServeWithListener(l),
			)
			a.NoError(err)
			go func() { _ = server.ListenAndServe() }()
			t.Cleanup(func() { _ = server.Close() })

			clientNet, serverNet := net.Pipe()
			clientConn := newConn(clientNet)
			t.Cleanup(func() {
				_ = clientConn.Close()
				_ = serverNet.Close()
			})
			sendConn(t, l, newConn(serverNet))
			if tc.dial {
				clientStore, cleanupClient := newTestStore(t)
				t.Cleanup(cleanupClient)
				dialer, err := NewDialer(
					"",
					clientStore,
					accept,
					DialWithFunc(func(string) (Conn, error) {
						return clientConn, nil
					}),
				)
				a.NoError(err)
				_, err = dialer.Dial()
				a.Error(err)
			} else {
				a.NoError(clientConn.Close())
			}

			deadline := time.Now().Add(10 * time.Second)
			for len(rec.levels(tc.msg)) == 0 {
				if time.Now().After(deadline) {
					a.FailNow("no log record", "%q", tc.msg)
				}
				time.Sleep(10 * time.Millisecond)
			}
			a.Equal([]slog.Level{tc.level}, rec.levels(tc.msg))
			if tc.level != slog.LevelError {
				a.Empty(rec.levels("serve conn"))
			}
		})
	}
}

func TestIntroTimeoutOptionRejectsNonPositive(t *testing.T) {
	a := require.New(t)
	store, cleanup := newTestStore(t)
	defer cleanup()
	verifier := func(*storage.Storage, *storage.Peer) error { return nil }
	for _, d := range []time.Duration{0, -time.Second} {
		_, err := NewServer(
			"", func(*Transport) error { return nil }, store, verifier,
			ServeWithIntroTimeout(d),
		)
		a.Error(err)
	}
}

// verifierRun is the outcome of one handshake run by runVerifierHandshake.
type verifierRun struct {
	dialErr    error
	serveErr   error
	handlerRan bool
}

// runVerifierHandshake runs one handshake over net.Pipe with the given
// verifiers. configure may adjust the server and dialer before it starts.
func runVerifierHandshake(
	t *testing.T,
	serverVerifier, dialVerifier RemoteVerifier,
	configure func(*Server, *Dialer),
) verifierRun {
	t.Helper()
	a := require.New(t)
	clientStore, cleanupClient := newTestStore(t)
	t.Cleanup(cleanupClient)
	serverStore, cleanupServer := newTestStore(t)
	t.Cleanup(cleanupServer)

	clientNet, serverNet := net.Pipe()
	clientConn := newConn(clientNet)
	serverConn := newConn(serverNet)
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	handled := make(chan struct{}, 1)
	server, err := NewServer(
		"",
		func(*Transport) error {
			handled <- struct{}{}
			return nil
		},
		serverStore,
		serverVerifier,
	)
	a.NoError(err)
	dialer, err := NewDialer(
		"",
		clientStore,
		dialVerifier,
		DialWithFunc(func(string) (Conn, error) { return clientConn, nil }),
	)
	a.NoError(err)
	configure(server, dialer)

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.serve(serverConn)
	}()
	tr, dialErr := dialer.Dial()
	if dialErr != nil {
		// Unblock a server still waiting for the dialer.
		_ = clientConn.Close()
	}

	var run verifierRun
	run.dialErr = dialErr
	// Close the dialer's side only once the server is done: a net.Pipe
	// whose other end is closed fails the server's SetDeadline.
	run.serveErr = <-serveErr
	if dialErr == nil {
		_ = tr.CloseAbort()
	}
	select {
	case <-handled:
		run.handlerRan = true
	default:
	}
	return run
}

func TestSlowVerifierOutlastsHandshakeDeadline(t *testing.T) {
	const timeout = time.Second
	accept := func(*storage.Storage, *storage.Peer) error { return nil }
	// slow accepts only after the handshake deadline set before the
	// verifier started has certainly passed.
	slow := func(*storage.Storage, *storage.Peer) error {
		time.Sleep(timeout + 500*time.Millisecond)
		return nil
	}
	cases := []struct {
		server RemoteVerifier
		dialer RemoteVerifier
		name   string
	}{
		{name: "slow server verifier", server: slow, dialer: accept},
		{name: "slow dialer verifier", server: accept, dialer: slow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			run := runVerifierHandshake(
				t, tc.server, tc.dialer, func(s *Server, d *Dialer) {
					s.handshakeOpts.timeout = timeout
					d.handshakeOpts.timeout = timeout
				},
			)
			a.NoError(run.dialErr)
			a.NoError(run.serveErr)
			a.True(run.handlerRan)
		})
	}
}

func TestLateVerifierAcceptIsRejected(t *testing.T) {
	const limit = 100 * time.Millisecond
	accept := func(*storage.Storage, *storage.Peer) error { return nil }
	late := func(*storage.Storage, *storage.Peer) error {
		time.Sleep(3 * limit)
		return nil
	}
	cases := []struct {
		server    RemoteVerifier
		dialer    RemoteVerifier
		configure func(*Server, *Dialer)
		name      string
		dialSide  bool
	}{
		{
			name:   "server verifier",
			server: late,
			dialer: accept,
			configure: func(s *Server, _ *Dialer) {
				s.handshakeOpts.verifyTimeout = limit
			},
		},
		{
			name:   "dialer verifier",
			server: accept,
			dialer: late,
			configure: func(_ *Server, d *Dialer) {
				d.handshakeOpts.verifyTimeout = limit
			},
			dialSide: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			run := runVerifierHandshake(t, tc.server, tc.dialer, tc.configure)
			a.Error(run.dialErr)
			a.Error(run.serveErr)
			a.False(run.handlerRan)
			if tc.dialSide {
				a.ErrorIs(run.dialErr, ErrVerificationFailed)
			} else {
				a.ErrorIs(run.serveErr, ErrVerificationFailed)
			}
		})
	}
}

func TestVerifyTimeoutOptionsRejectNonPositive(t *testing.T) {
	a := require.New(t)
	store, cleanup := newTestStore(t)
	defer cleanup()
	verifier := func(*storage.Storage, *storage.Peer) error { return nil }
	for _, d := range []time.Duration{0, -time.Second} {
		_, err := NewServer(
			"", func(*Transport) error { return nil }, store, verifier,
			ServeWithVerifyTimeout(d),
		)
		a.Error(err)
		_, err = NewDialer("", store, verifier, DialWithVerifyTimeout(d))
		a.Error(err)
	}
}

// stubbornConn ignores Close until the test ends, so a handshake can complete
// after the server has tried to close the connection.
type stubbornConn struct {
	Conn
}

func (stubbornConn) Close() error { return nil }

func TestCloseStopsHandshakesInProgress(t *testing.T) {
	cases := []struct {
		wrap func(Conn) Conn
		name string
		// completes is whether the handshake still completes after Close.
		completes bool
	}{
		{name: "pending connection is closed", wrap: func(c Conn) Conn { return c }},
		{
			name:      "handshake completing after close",
			wrap:      func(c Conn) Conn { return stubbornConn{Conn: c} },
			completes: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			clientStore, cleanupClient := newTestStore(t)
			defer cleanupClient()
			serverStore, cleanupServer := newTestStore(t)
			defer cleanupServer()

			verifying := make(chan struct{})
			release := make(chan struct{})
			handlerRan := make(chan struct{}, 1)
			l := newTestListener(net.ErrClosed)
			server, err := NewServer(
				"",
				func(*Transport) error {
					handlerRan <- struct{}{}
					return nil
				},
				serverStore,
				func(*storage.Storage, *storage.Peer) error {
					close(verifying)
					<-release
					return nil
				},
				ServeWithListener(l),
			)
			a.NoError(err)
			result := make(chan error, 1)
			go func() { result <- server.ListenAndServe() }()

			clientNet, serverNet := net.Pipe()
			clientConn := newConn(clientNet)
			serverConn := newConn(serverNet)
			t.Cleanup(func() {
				_ = clientConn.Close()
				_ = serverConn.Close()
			})
			l.conns <- tc.wrap(serverConn)

			dialer, err := NewDialer(
				"",
				clientStore,
				func(*storage.Storage, *storage.Peer) error { return nil },
				DialWithFunc(func(string) (Conn, error) {
					return clientConn, nil
				}),
			)
			a.NoError(err)
			// The dialer reads as soon as it has a session, so a close
			// frame from the server can be delivered over the pipe.
			type dialResult struct {
				dialErr error
				recvErr error
			}
			dialed := make(chan dialResult, 1)
			go func() {
				tr, err := dialer.Dial()
				if err != nil {
					dialed <- dialResult{dialErr: err}
					return
				}
				_, err = tr.Receive(Bytes(nil))
				dialed <- dialResult{recvErr: err}
			}()

			<-verifying
			a.NoError(server.Close())
			close(release)

			ctx, cancel := context.WithTimeout(
				context.Background(), 10*time.Second,
			)
			defer cancel()
			a.NoError(server.Shutdown(ctx))
			a.NoError(<-result)
			a.Empty(handlerRan, "handler started after Close")
			sessions, err := serverStore.ListSessions()
			a.NoError(err)
			a.Empty(sessions, "session stored for a handshake dropped at Close")

			got := <-dialed
			if !tc.completes {
				a.Error(got.dialErr)
				return
			}
			a.NoError(got.dialErr)
			a.ErrorIs(got.recvErr, ErrPeerDisconnected)
		})
	}
}

func TestShutdownWaitsForHandlers(t *testing.T) {
	a := require.New(t)
	clientStore, cleanupClient := newTestStore(t)
	defer cleanupClient()
	serverStore, cleanupServer := newTestStore(t)
	defer cleanupServer()

	verifier := func(*storage.Storage, *storage.Peer) error { return nil }
	started := make(chan struct{})
	release := make(chan struct{})
	l := newTestListener(net.ErrClosed)
	server, err := NewServer(
		"",
		func(*Transport) error {
			close(started)
			<-release
			return nil
		},
		serverStore,
		verifier,
		ServeWithListener(l),
	)
	a.NoError(err)
	result := make(chan error, 1)
	go func() { result <- server.ListenAndServe() }()

	clientNet, serverNet := net.Pipe()
	clientConn := newConn(clientNet)
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverNet.Close()
	})
	l.conns <- newConn(serverNet)
	dialer, err := NewDialer(
		"",
		clientStore,
		verifier,
		DialWithFunc(func(string) (Conn, error) { return clientConn, nil }),
	)
	a.NoError(err)
	_, err = dialer.Dial()
	a.NoError(err)
	<-started

	short, cancelShort := context.WithTimeout(
		context.Background(), 50*time.Millisecond,
	)
	defer cancelShort()
	a.ErrorIs(server.Shutdown(short), context.DeadlineExceeded)
	a.NoError(<-result)

	close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a.NoError(server.Shutdown(ctx))
}

func TestNewServerFailureLeavesPortFree(t *testing.T) {
	errOption := errors.New("option failed")
	failing := func(*Server) error { return errOption }
	cases := []struct {
		freeAddr func(a *require.Assertions) string
		bind     func(addr string) (io.Closer, error)
		option   ServerOptions
		name     string
	}{
		{
			name:   "tcp",
			option: ServeWithTCP(),
			freeAddr: func(a *require.Assertions) string {
				l, err := net.Listen("tcp", "127.0.0.1:0")
				a.NoError(err)
				addr := l.Addr().String()
				a.NoError(l.Close())
				return addr
			},
			bind: func(addr string) (io.Closer, error) {
				return net.Listen("tcp", addr)
			},
		},
		{
			name:   "udp",
			option: ServeWithUDP(),
			freeAddr: func(a *require.Assertions) string {
				c, err := net.ListenPacket("udp", "127.0.0.1:0")
				a.NoError(err)
				addr := c.LocalAddr().String()
				a.NoError(c.Close())
				return addr
			},
			bind: func(addr string) (io.Closer, error) {
				return net.ListenPacket("udp", addr)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			store, cleanup := newTestStore(t)
			defer cleanup()
			verifier := func(*storage.Storage, *storage.Peer) error {
				return nil
			}
			handler := func(*Transport) error { return nil }
			addr := tc.freeAddr(a)

			_, err := NewServer(
				addr, handler, store, verifier, tc.option, failing,
			)
			a.ErrorIs(err, errOption)
			c, err := tc.bind(addr)
			a.NoError(err, "port left bound by the failed NewServer")
			a.NoError(c.Close())

			// A successful NewServer still binds the port.
			server, err := NewServer(addr, handler, store, verifier, tc.option)
			a.NoError(err)
			defer server.Close()
			c, err = tc.bind(addr)
			if err == nil {
				_ = c.Close()
			}
			a.Error(err, "NewServer did not bind the port")
		})
	}
}

// resumeDial resumes sessionID from clientStore against a server on
// serverStore that runs verifier. It returns the dialer's error and, once
// the server is done, the server's.
func resumeDial(
	t *testing.T,
	clientStore, serverStore *storage.Storage,
	sessionID string,
	verifier RemoteVerifier,
	opts ...ServerOptions,
) (error, error) {
	t.Helper()
	a := require.New(t)
	clientNet, serverNet := net.Pipe()
	clientConn := newConn(clientNet)
	serverConn := newConn(serverNet)
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	server, err := NewServer(
		"",
		func(tr *Transport) error {
			_, err := tr.Send(Bytes([]byte("resumed")), RouteExchangeMessages)
			return err
		},
		serverStore,
		verifier,
		opts...,
	)
	a.NoError(err)
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.serve(serverConn)
	}()

	dialer, err := NewDialer(
		"",
		clientStore,
		verifier,
		DialWithResume(sessionID),
		DialWithFunc(func(string) (Conn, error) {
			return clientConn, nil
		}),
	)
	a.NoError(err)
	tr, dialErr := dialer.Dial()
	if dialErr == nil {
		msg := Bytes(nil)
		_, err = tr.Receive(msg)
		a.NoError(err)
		a.Equal([]byte("resumed"), msg.Value)
	}
	return dialErr, <-serveErr
}

// TestResumeSkipsVerifierUntilPeerDeleted pins what the docs of
// ServeWithResumeEnabled and RemoteVerifier say: a resumed session runs no
// verifier, and deleting the peer from the server's storage stops it from
// resuming.
func TestResumeSkipsVerifierUntilPeerDeleted(t *testing.T) {
	a := require.New(t)
	clientStore, cleanupClient := newTestStore(t)
	defer cleanupClient()
	serverStore, cleanupServer := newTestStore(t)
	defer cleanupServer()

	sessionID := coldDial(t, clientStore, serverStore)

	var calls atomic.Int32
	verifier := func(*storage.Storage, *storage.Peer) error {
		calls.Add(1)
		return errors.New("verifier must not run")
	}
	dialErr, serveErr := resumeDial(
		t, clientStore, serverStore, sessionID, verifier,
	)
	a.NoError(dialErr)
	a.NoError(serveErr)
	a.Zero(calls.Load())

	clientKey, err := clientStore.PublicKey()
	a.NoError(err)
	a.NoError(serverStore.DeletePeer(clientKey))
	dialErr, serveErr = resumeDial(
		t, clientStore, serverStore, sessionID, verifier,
	)
	a.ErrorIs(dialErr, ErrResumptionRejected)
	a.Error(serveErr)
}

// TestResumeWindowStartsAtColdHandshake checks that resuming a session does
// not extend its resumption window, which counts from the cold handshake.
func TestResumeWindowStartsAtColdHandshake(t *testing.T) {
	a := require.New(t)
	fake := clock.NewFake(time.Now())
	clientStore, cleanupClient := newTestStore(t)
	defer cleanupClient()
	serverStore, cleanupServer := newTestStore(t, storage.WithClock(fake))
	defer cleanupServer()

	sessionID := coldDial(t, clientStore, serverStore)
	cold, err := serverStore.GetEstablishedAt(sessionID)
	a.NoError(err)

	accept := func(*storage.Storage, *storage.Peer) error { return nil }
	fake.Advance(20 * time.Hour)
	dialErr, serveErr := resumeDial(
		t, clientStore, serverStore, sessionID, accept, ServeWithClock(fake),
	)
	a.NoError(dialErr)
	a.NoError(serveErr)
	after, err := serverStore.GetEstablishedAt(sessionID)
	a.NoError(err)
	a.True(cold.Equal(after))

	// 25 hours after the cold handshake but 5 after the resumption.
	fake.Advance(5 * time.Hour)
	dialErr, serveErr = resumeDial(
		t, clientStore, serverStore, sessionID, accept, ServeWithClock(fake),
	)
	a.ErrorIs(dialErr, ErrResumptionRejected)
	a.ErrorContains(serveErr, "session expired")
}
