package kamune

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

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
