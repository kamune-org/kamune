package kamune

import (
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
