package kamune

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

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
