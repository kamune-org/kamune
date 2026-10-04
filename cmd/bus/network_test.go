package main

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
)

// tcpTestListener hands kamune the connections of a plain TCP listener,
// so a test server can listen on a port the kernel picks.
type tcpTestListener struct{ net.Listener }

func (l tcpTestListener) Accept() (kamune.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return kamune.NewConn(c), nil
}

func openTestStorage(t *testing.T) *storage.Storage {
	t.Helper()
	a := require.New(t)
	f, err := os.CreateTemp("", "kamune-bus-server-test-*.db")
	a.NoError(err)
	a.NoError(f.Close())
	t.Cleanup(func() { _ = os.Remove(f.Name()) })

	store, err := storage.OpenStorage(
		storage.WithDBPath(f.Name()),
		storage.WithNoPassphrase(),
		storage.WithExpiryDuration(24*time.Hour),
	)
	a.NoError(err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// startTestServer runs a kamune server that introduces itself as name and
// admits every peer. It returns the server's address and public key.
func startTestServer(
	t *testing.T, name string, handler kamune.HandlerFunc,
) (string, []byte) {
	t.Helper()
	a := require.New(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	a.NoError(err)

	srv, err := kamune.NewServer(
		"", handler, openTestStorage(t),
		func(*storage.Storage, *storage.Peer) error { return nil },
		kamune.ServeWithListener(tcpTestListener{ln}),
		kamune.ServeWithServerName(name),
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
	return ln.Addr().String(), srv.PublicKey()
}

func TestPinPeer(t *testing.T) {
	cases := []struct {
		name    string
		pinned  bool
		match   bool
		wantErr error
		wantRun bool
	}{
		{name: "no pin", wantRun: true},
		{name: "matching key", pinned: true, match: true, wantRun: true},
		{name: "other key", pinned: true, wantErr: ErrPeerKeyMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			app, cleanup := newTestAppWithStorage(t)
			defer cleanup()

			peer := newTestPeer(t, "Bob")
			var want []byte
			if tc.pinned {
				want = newTestPubKey(t)
				if tc.match {
					want = peer.PublicKey
				}
			}
			ran := false
			rv := app.pinPeer(want, func(*storage.Storage, *storage.Peer) error {
				ran = true
				return nil
			})

			err := rv(app.store(), peer)
			if tc.wantErr != nil {
				a.ErrorIs(err, tc.wantErr)
			} else {
				a.NoError(err)
			}
			a.Equal(tc.wantRun, ran)
		})
	}
}

// TestConnectToServerRejectsOtherKnownPeer is the BUS-01 scenario: Mallory
// is a stored peer and answers a connection the user opened to Bob,
// introducing herself as Bob. Quick mode used to admit her silently.
func TestConnectToServerRejectsOtherKnownPeer(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()
	app.verifMode = VerificationModeQuick
	store := app.store()

	addr, malloryKey := startTestServer(t, "Bob",
		func(*kamune.Transport) error { return nil })
	a.NoError(store.StorePeer(&storage.Peer{
		Name: "Mallory", PublicKey: malloryKey,
	}))
	bobKey := newTestPubKey(t)
	a.NoError(store.StorePeer(&storage.Peer{
		Name: "Bob", PublicKey: bobKey,
	}))
	app.refreshPeersCache()

	res, err := app.ConnectToServer(
		addr, "tcp", "", "", "alice", "", "",
		fingerprint.Base64(bobKey), "", false, false,
	)
	a.Error(err)
	a.True(errors.Is(err, ErrPeerKeyMismatch), "got %v", err)
	a.Equal("peer_key_mismatch", res.ErrorCode)
	a.Empty(app.GetSessions())
	a.Empty(pendingIDs(app))
}

func TestConnectToServerRejectsBadPeerKey(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	res, err := app.ConnectToServer(
		"127.0.0.1:1", "tcp", "", "", "alice", "", "",
		"not-a-key", "", false, false,
	)
	a.Error(err)
	a.Equal("invalid_peer_key", res.ErrorCode)
}
