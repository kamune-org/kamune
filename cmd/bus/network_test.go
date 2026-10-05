package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/relayconn"
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
		fingerprint.Base64(bobKey), "", false, false, "",
	)
	a.Error(err)
	a.True(errors.Is(err, ErrPeerKeyMismatch), "got %v", err)
	a.Equal("peer_key_mismatch", res.ErrorCode)
	requireWindowErrorCode(t, err, "peer_key_mismatch")
	a.Empty(app.GetSessions())
	a.Empty(pendingIDs(app))
}

// TestRelayDialToken checks which relay token a dial joins: a token the
// user gave, also along with a peer, whose key ConnectToServer then pins,
// and otherwise the static token derived for the peer.
func TestRelayDialToken(t *testing.T) {
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()
	peer := fingerprint.Base64(newTestPubKey(t))
	static, err := app.deriveP2PToken(peer)
	require.New(t).NoError(err)

	tests := []struct {
		name, token, peer, want string
		wantErr                 bool
	}{
		{name: "token", token: "ab12", want: "ab12"},
		{name: "peer", peer: peer, want: hex.EncodeToString(static)},
		{name: "token and peer", token: "ab12", peer: peer, want: "ab12"},
		{name: "neither"},
		{name: "bad peer key", peer: "not-a-key", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			got, err := app.relayDialToken(tc.token, tc.peer)
			if tc.wantErr {
				a.Error(err)
				return
			}
			a.NoError(err)
			a.Equal(tc.want, got)
		})
	}
}

func TestConnectToServerRejectsBadPeerKey(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()

	res, err := app.ConnectToServer(
		"127.0.0.1:1", "tcp", "", "", "alice", "", "",
		"not-a-key", "", false, false, "",
	)
	a.Error(err)
	a.Equal("invalid_peer_key", res.ErrorCode)
	requireWindowErrorCode(t, err, "invalid_peer_key")
}

// TestDialErrorCode checks the error code of a failed dial: a dial over
// a punched socket failed to punch only when nothing came from the peer.
func TestDialErrorCode(t *testing.T) {
	answered := &punchSession{}
	answered.answered.Store(true)
	errClosed := errors.New("connection closed")
	cases := []struct {
		name    string
		err     error
		punched *punchSession
		want    string
	}{
		{name: "other key", err: ErrPeerKeyMismatch,
			want: "peer_key_mismatch"},
		{name: "rejected", err: fmt.Errorf("verify remote: %w",
			kamune.ErrVerificationFailed), want: "verification_rejected"},
		{name: "rejected over a punch", err: kamune.ErrVerificationFailed,
			punched: answered, want: "verification_rejected"},
		{name: "rejected before the peer answered",
			err: kamune.ErrVerificationFailed, punched: &punchSession{},
			want: "verification_rejected"},
		{name: "prompt cancelled", err: ErrVerificationCancelled,
			want: "verification_rejected"},
		{name: "no answer over a punch", err: errClosed,
			punched: &punchSession{}, want: "hole_punch_failed"},
		{name: "handshake failed over a punch", err: errClosed,
			punched: answered, want: "dial_failed"},
		{name: "version mismatch over a punch",
			err: kamune.ErrVersionMismatch, punched: answered,
			want: "dial_failed"},
		{name: "no punch", err: errClosed, want: "dial_failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.New(t).Equal(tc.want, dialErrorCode(tc.err, tc.punched))
		})
	}
}

// TestConnectToServerP2PRejectedIsNotPunchFailure dials a peer by direct
// P2P in Strict mode and rejects it in the prompt. The punch worked, so
// the call must not report hole_punch_failed, which would offer to try
// the peer again or through a relay.
func TestConnectToServerP2PRejectedIsNotPunchFailure(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()
	app.verifMode = VerificationModeStrict

	l, err := newDirectP2PListener("127.0.0.1:0", "127.0.0.1:9")
	a.NoError(err)
	srv, err := kamune.NewServer(
		"", func(*kamune.Transport) error { return nil },
		openTestStorage(t), acceptAll,
		kamune.ServeWithListener(l), kamune.ServeWithServerName("Bob"),
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

	type outcome struct {
		res ConnectResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := app.ConnectToServer(
			l.Addr().String(), "udp", "", "", "alice", "", "", "", "",
			true, false, "",
		)
		done <- outcome{res, err}
	}()
	ids := waitPending(t, app, 1)
	app.VerifyResponse(ids[0], false)

	var got outcome
	select {
	case got = <-done:
	case <-time.After(testWait):
		a.FailNow("the dial did not return")
	}
	a.ErrorIs(got.err, kamune.ErrVerificationFailed)
	a.Equal("verification_rejected", got.res.ErrorCode)
	requireWindowErrorCode(t, got.err, "verification_rejected")
	a.Empty(app.GetSessions())
}

// requireWindowErrorCode checks that err, which a ConnectToServer call
// returned, gives the window the error code code. Wails drops the
// ConnectResult of a call that returns an error, and passes the window
// the error's JSON form, which it makes with json.Marshal(&err), as the
// cause of the rejection.
func requireWindowErrorCode(t *testing.T, err error, code string) {
	t.Helper()
	a := require.New(t)
	cause, jsonErr := json.Marshal(&err)
	a.NoError(jsonErr)
	a.JSONEq(`{"errorCode":"`+code+`"}`, string(cause))
}

// gatedTestListener tags every accepted conn with gate, as the relay and
// p2p listeners do for a token made for one peer.
type gatedTestListener struct {
	net.Listener
	gate peerGate
}

func (l gatedTestListener) Accept() (kamune.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &gatedConn{Conn: kamune.NewConn(c), gate: l.gate}, nil
}

func TestPeerKeySet(t *testing.T) {
	k1, k2 := []byte("key-one"), []byte("key-two")
	cases := []struct {
		name  string
		allow [][]byte
		want1 bool
		want2 bool
	}{
		{name: "not pinned", want1: true, want2: true},
		{name: "one peer", allow: [][]byte{k1}, want1: true},
		{name: "two peers", allow: [][]byte{k1, k2}, want1: true, want2: true},
		{name: "open", allow: [][]byte{nil}, want1: true, want2: true},
		{name: "peer then open", allow: [][]byte{k1, nil},
			want1: true, want2: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			var s peerKeySet
			for _, k := range tc.allow {
				s.allow(k)
			}
			a.Equal(tc.want1, s.admitsPeer(k1))
			a.Equal(tc.want2, s.admitsPeer(k2))
			a.Equal(tc.want1, admittedBy(&s, k1))
		})
	}
	require.New(t).True(admittedBy(nil, k1))
}

// TestServerHandlerChecksTokenPeer runs the bus server handler behind a
// listener whose token was made for Bob. Mallory, introducing herself as
// Bob, must be dropped; Bob must be admitted.
func TestServerHandlerChecksTokenPeer(t *testing.T) {
	cases := []struct {
		name    string
		isBob   bool
		wantRun bool
	}{
		{name: "other peer is dropped"},
		{name: "token's peer is admitted", isBob: true, wantRun: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			app, cleanup := newTestAppWithStorage(t)
			defer cleanup()
			app.serverVerifMode = VerificationModeAutoAccept

			dialStore := openTestStorage(t)
			dialKey, err := dialStore.PublicKey()
			a.NoError(err)
			bobKey := newTestPubKey(t)
			if tc.isBob {
				bobKey = dialKey
			}
			var gate peerKeySet
			gate.allow(bobKey)

			ln, err := net.Listen("tcp", "127.0.0.1:0")
			a.NoError(err)
			acceptAll := func(*storage.Storage, *storage.Peer) error {
				return nil
			}
			var srv *kamune.Server
			handler := func(t *kamune.Transport) error {
				return app.serverHandler(srv, t)
			}
			srv, err = kamune.NewServer(
				"", handler, app.store(), acceptAll,
				kamune.ServeWithListener(gatedTestListener{ln, &gate}),
			)
			a.NoError(err)
			app.mu.Lock()
			app.server = srv
			app.mu.Unlock()
			done := make(chan struct{})
			go func() {
				defer close(done)
				_ = srv.ListenAndServe()
			}()
			defer func() {
				_ = srv.Close()
				<-done
			}()

			d, err := kamune.NewDialer(
				ln.Addr().String(), dialStore, acceptAll,
				kamune.DialWithTCP(), kamune.DialWithClientName("Bob"),
			)
			a.NoError(err)
			tr, err := d.Dial()
			a.NoError(err)
			defer func() { _ = tr.Close() }()

			if tc.wantRun {
				a.Eventually(func() bool {
					return len(app.GetSessions()) == 1
				}, testWait, time.Millisecond)
				a.NoError(tr.Close())
				a.Eventually(func() bool {
					return len(app.GetSessions()) == 0
				}, testWait, time.Millisecond)
				return
			}

			// The handler closes a dropped session; wait for that.
			a.NoError(tr.SetDeadline(time.Now().Add(testWait)))
			for {
				_, _, err := tr.ReceivePayload()
				if err != nil {
					a.NotErrorIs(err, kamune.ErrReceiveTimeout)
					break
				}
			}
			a.Empty(app.GetSessions())
			_, err = app.store().FindPeer(dialKey)
			a.Error(err, "a dropped peer must not be saved")
		})
	}
}

func TestServerHandlerDropsSessionOfStoppedServer(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()
	app.serverVerifMode = VerificationModeAutoAccept

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	a.NoError(err)
	acceptAll := func(*storage.Storage, *storage.Peer) error { return nil }
	// srv is not the app's server, as after StopServer has taken it out
	// while a handshake was still in progress.
	var srv *kamune.Server
	handler := func(t *kamune.Transport) error {
		return app.serverHandler(srv, t)
	}
	srv, err = kamune.NewServer(
		"", handler, app.store(), acceptAll,
		kamune.ServeWithListener(tcpTestListener{ln}),
	)
	a.NoError(err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.ListenAndServe()
	}()
	defer func() {
		_ = srv.Close()
		<-done
	}()

	d, err := kamune.NewDialer(
		ln.Addr().String(), openTestStorage(t), acceptAll,
		kamune.DialWithTCP(),
	)
	a.NoError(err)
	tr, err := d.Dial()
	a.NoError(err)
	defer func() { _ = tr.Close() }()

	a.NoError(tr.SetDeadline(time.Now().Add(testWait)))
	_, _, err = tr.ReceivePayload()
	a.ErrorIs(err, kamune.ErrPeerDisconnected)
	a.Empty(app.GetSessions())
}

// TestRelayRejectsBadPeerKey checks that a relay server or relay token
// asked for a peer whose key cannot be used fails, instead of falling
// back to a random token that peer never learns.
func TestRelayRejectsBadPeerKey(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.New(t).NoError(err)
	// Nothing listens on the relay address any more, so a fallback to a
	// random token would fail differently.
	relayAddr := "tcp://" + ln.Addr().String()
	require.New(t).NoError(ln.Close())
	badKey := fingerprint.Base64(make([]byte, 44))

	cases := []struct {
		name string
		run  func(app *App) error
	}{
		{name: "start server", run: func(app *App) error {
			_, _, err := app.StartServer(
				"", "relay", relayAddr, "", "", "", badKey,
				false, false, "",
			)
			return err
		}},
		{name: "generate token", run: func(app *App) error {
			app.mu.Lock()
			app.relayListeners = newMultiListener()
			app.relayAddr = relayAddr
			app.mu.Unlock()
			_, err := app.GenerateRelayToken(badKey)
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			app, cleanup := newTestAppWithStorage(t)
			defer cleanup()
			err := tc.run(app)
			a.ErrorContains(err, "derive static relay token")
			a.Empty(app.GetRelayTokens())
			a.False(app.GetServerStatus().Running)
		})
	}
}

// TestGetShareInfoP2P checks that a P2P server reports that it has no
// share card rather than an unknown transport.
func TestGetShareInfoP2P(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	a.NoError(err)
	defer ln.Close()
	srv, err := kamune.NewServer(
		"", func(*kamune.Transport) error { return nil }, app.store(),
		func(*storage.Storage, *storage.Peer) error { return nil },
		kamune.ServeWithListener(tcpTestListener{ln}),
	)
	a.NoError(err)
	app.mu.Lock()
	app.server = srv
	app.serverTransportType = "p2p"
	app.mu.Unlock()

	_, err = app.GetShareInfo()
	a.ErrorIs(err, ErrNoShareCard)
}

// TestFinishRelayTokenStoresPool runs the relay token exchange between
// two ends of a session and checks that the app stores the derived pool
// for a session in storage, and that one no longer in storage, such as
// one deleted from the history while it ran, is let go without a
// warning.
func TestFinishRelayTokenStoresPool(t *testing.T) {
	cases := []struct {
		name   string
		stored bool
	}{
		{"session in storage", true},
		{"session no longer in storage", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			app, _ := newUnlockedApp(t, "secret")
			peers := make(chan *kamune.Transport, 1)
			release := make(chan struct{})
			addr, _ := startTestServer(t, "srv",
				func(tr *kamune.Transport) error {
					peers <- tr
					<-release
					return nil
				})
			t.Cleanup(func() { close(release) })
			d, err := kamune.NewDialer(
				addr, app.store(), acceptAll, kamune.DialWithTCP(),
			)
			a.NoError(err)
			tr, err := d.Dial()
			a.NoError(err)
			t.Cleanup(func() { _ = tr.CloseAbort() })
			peer := <-peers
			id := tr.SessionID()
			if !tc.stored {
				a.NoError(app.store().DeleteSession(id))
			}

			pending, err := relayconn.BeginRelayTokenExchange(tr)
			a.NoError(err)
			_, err = relayconn.BeginRelayTokenExchange(peer)
			a.NoError(err)
			a.NoError(tr.SetDeadline(time.Now().Add(testWait)))
			md, payload, err := tr.ReceivePayload()
			a.NoError(err)
			a.Equal(kamune.RouteSessionData, md.Route())

			session := &liveSession{ID: id, relayToken: pending}
			app.finishRelayToken(session, payload)

			a.Nil(session.relayToken, "the exchange is over")
			pool := loadRelayPool(app.store(), id)
			if tc.stored {
				a.NotEmpty(pool)
			} else {
				a.Empty(pool)
				sessions, err := app.store().ListSessions()
				a.NoError(err)
				a.NotContains(sessions, id,
					"the session must not be stored again")
			}
			for _, e := range app.GetLogEntries() {
				a.NotEqual("WARN", e.Level, e.Message)
			}
		})
	}
}
