package handlers

import (
	"net"
	"testing"
	"time"

	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/relayconn/pb"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/kamune-org/kamune/cmd/relay/internal/services"
)

// newTestHub builds a Hub with the given handshake timeout and a small
// SessionManager suitable for tests.
func newTestHub(
	t *testing.T,
	password string,
	handshakeTimeout time.Duration,
) *services.Hub {
	t.Helper()
	sm := services.NewSessionManager(time.Minute, 100, 0)
	return services.NewHub(sm, password, 0, nil, handshakeTimeout)
}

// dialClient drives a fake client over the given net.Conn: it performs
// the HPKE Initiate, sends optional auth, sends the register frame, reads
// the Registered response, and returns the response frame and the
// client-side exchange.Channel. If auth is required but not provided,
// authPassword must equal password.
func dialClient(
	t *testing.T,
	conn net.Conn,
	password, authPassword string,
	mode pb.Register_Mode,
	token []byte,
) (*exchange.Channel, *pb.Registered) {
	t.Helper()
	a := require.New(t)

	ch, err := exchange.Initiate(newRawTCPAdapter(conn, 0))
	a.NoError(err, "Initiate")

	if password != "" {
		a.NotEmpty(authPassword, "dialClient: password required but authPassword empty")
		auth := &pb.Frame{
			Kind: &pb.Frame_Auth{Auth: &pb.Auth{Psk: []byte(authPassword)}},
		}
		b, err := proto.Marshal(auth)
		a.NoError(err, "marshal auth")
		a.NoError(ch.WriteBytes(b), "write auth")
		// Drain the ack.
		_, err = ch.ReadBytes()
		a.NoError(err, "read auth ack")
	}

	reg := &pb.Frame{
		Kind: &pb.Frame_Register{Register: &pb.Register{
			Mode:  mode,
			Token: token,
		}},
	}
	b, err := proto.Marshal(reg)
	a.NoError(err, "marshal register")
	a.NoError(ch.WriteBytes(b), "write register")

	resp, err := ch.ReadBytes()
	a.NoError(err, "read registered")
	var f pb.Frame
	a.NoError(proto.Unmarshal(resp, &f), "unmarshal registered")
	reg2 := f.GetRegistered()
	a.NotNil(reg2, "expected Registered frame, got %T", f.Kind)
	return ch, reg2
}

// sendFrame marshals and writes a Frame over the exchange channel.
func sendFrame(t *testing.T, ch *exchange.Channel, f *pb.Frame) {
	t.Helper()
	a := require.New(t)
	b, err := proto.Marshal(f)
	a.NoError(err, "marshal")
	a.NoError(ch.WriteBytes(b), "write")
}

// readFrame reads a single Frame from the channel.
func readFrame(t *testing.T, ch *exchange.Channel) *pb.Frame {
	t.Helper()
	a := require.New(t)
	b, err := ch.ReadBytes()
	a.NoError(err, "read")
	var f pb.Frame
	a.NoError(proto.Unmarshal(b, &f), "unmarshal")
	return &f
}

// runServer runs handleRelayConn on a goroutine and returns a cancel
// function that, when called, closes the server-side net.Conn and waits
// for the handler to return. The handshake timer (if non-nil) is passed
// to handleRelayConn so its lifecycle can be observed.
func runServer(
	hub *services.Hub,
	conn net.Conn,
	handshakeTimer *time.Timer,
) (stop func()) {
	serverDone := make(chan struct{})
	go func() {
		adapter := newRawTCPAdapter(conn, hub.MaxMessageSize())
		handleRelayConn(hub, adapter, "test", handshakeTimer)
		close(serverDone)
	}()
	return func() {
		_ = conn.Close()
		<-serverDone
	}
}

// TestRelay_HandshakeTimeout_AppliesOnlyToHandshake is the regression
// test for the bug where the handshake timeout context/deadline leaked
// into the post-handshake session. With the fix, the timer is stopped
// after registration and a message exchanged after the timeout must
// still succeed.
func TestRelay_HandshakeTimeout_AppliesOnlyToHandshake(t *testing.T) {
	a := require.New(t)
	hub := newTestHub(t, "", 80*time.Millisecond)

	// Listener side: we drive the client end and run the server end.
	listenerClient, listenerServer := net.Pipe()
	defer listenerClient.Close()
	defer listenerServer.Close()

	// Dialer side.
	dialerClient, dialerServer := net.Pipe()
	defer dialerClient.Close()
	defer dialerServer.Close()

	// Per-connection handshake timers, the same way WebSocketHandler
	// creates them. The TCP/TLS path passes nil.
	listenerTimer := time.AfterFunc(
		hub.HandshakeTimeout(),
		func() { _ = listenerServer.Close() },
	)

	stopListener := runServer(hub, listenerServer, listenerTimer)
	stopDialer := runServer(hub, dialerServer, nil)

	// Listener: empty token, creates a session.
	listenerCh, reg := dialClient(t, listenerClient, "", "", pb.Register_MODE_CREATE, nil)
	a.Greater(reg.GetTtlSeconds(), uint32(0))
	token := reg.GetToken()
	a.Len(token, 16)

	// Timer should be stopped after handshake completes.
	time.Sleep(20 * time.Millisecond)
	a.False(listenerTimer.Stop(), "listenerTimer was not stopped after registration")

	// Dialer joins with the listener's token.
	dialerCh, _ := dialClient(t, dialerClient, "", "", pb.Register_MODE_JOIN, token)

	// Wait past the original handshake timeout to make sure the session
	// is not killed by it.
	time.Sleep(2 * hub.HandshakeTimeout())

	// Exchange a message: listener → dialer.
	want := []byte("hello from listener")
	sendFrame(t, listenerCh, &pb.Frame{
		Kind: &pb.Frame_Msg{Msg: &pb.Message{Data: want}},
	})
	got := readFrame(t, dialerCh)
	a.NotNil(got.GetMsg(), "expected Msg frame, got %T", got.Kind)
	a.Equal(want, got.GetMsg().GetData())

	// And dialer → listener.
	want2 := []byte("hello from dialer")
	sendFrame(t, dialerCh, &pb.Frame{
		Kind: &pb.Frame_Msg{Msg: &pb.Message{Data: want2}},
	})
	got2 := readFrame(t, listenerCh)
	a.NotNil(got2.GetMsg(), "expected Msg frame, got %T", got2.Kind)
	a.Equal(want2, got2.GetMsg().GetData())

	stopListener()
	stopDialer()
}

// TestRelay_Disconnect_ClosesPeer ensures that closing one peer's
// underlying connection causes the other peer's channel to close
// (via ClosePeerChannel) and ReadPump to exit.
func TestRelay_Disconnect_ClosesPeer(t *testing.T) {
	a := require.New(t)
	hub := newTestHub(t, "", 0)

	listenerClient, listenerServer := net.Pipe()
	dialerClient, dialerServer := net.Pipe()

	stopListener := runServer(hub, listenerServer, nil)
	stopDialer := runServer(hub, dialerServer, nil)
	defer stopListener()
	defer stopDialer()

	listenerCh, reg := dialClient(t, listenerClient, "", "", pb.Register_MODE_CREATE, nil)
	token := reg.GetToken()
	dialerCh, _ := dialClient(t, dialerClient, "", "", pb.Register_MODE_JOIN, token)

	// The listener is mid-ReadPump. If we close the dialer side, the
	// relay should detect the close and tear down the listener too.
	_ = dialerCh

	// ReadPump blocks on ReadBytes; closing the dialer's pipe causes a
	// read error on the relay side, which triggers the disconnect
	// cleanup.
	_ = dialerClient.Close()
	_ = dialerServer.Close()

	// The listener's ReadBytes on its channel should return an error
	// once ClosePeerChannel closes its underlying pipe.
	readErr := make(chan error, 1)
	go func() {
		_, err := listenerCh.ReadBytes()
		readErr <- err
	}()

	select {
	case err := <-readErr:
		a.Error(err, "listener ReadBytes returned nil after peer disconnect")
	case <-time.After(2 * time.Second):
		a.FailNow("listener ReadBytes did not return after peer disconnect")
	}

	_ = listenerClient.Close()
	_ = listenerServer.Close()
}

// TestRelay_Auth_Required exercises the password path end-to-end.
func TestRelay_Auth_Required(t *testing.T) {
	a := require.New(t)
	const password = "s3kret"
	hub := newTestHub(t, password, 0)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	stop := runServer(hub, server, nil)
	defer stop()

	ch, reg := dialClient(t, client, password, password, pb.Register_MODE_CREATE, nil)
	a.NotNil(reg, "Registered is nil")
	_ = ch.Close()
}

// TestRelay_Auth_WrongPSK verifies that a wrong password causes the
// relay to close the connection (we expect a read error from the
// client's side).
func TestRelay_Auth_WrongPSK(t *testing.T) {
	a := require.New(t)
	hub := newTestHub(t, "right", 0)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	stop := runServer(hub, server, nil)
	defer stop()

	// The client does HPKE Initiate, then sends auth with wrong PSK.
	// The server should close before we ever see a Registered frame.
	ch, err := exchange.Initiate(newRawTCPAdapter(client, 0))
	a.NoError(err, "Initiate")
	defer ch.Close()

	auth := &pb.Frame{
		Kind: &pb.Frame_Auth{Auth: &pb.Auth{Psk: []byte("wrong")}},
	}
	b, _ := proto.Marshal(auth)
	a.NoError(ch.WriteBytes(b), "write auth")

	// The relay closes the connection. We expect an error reading
	// either the auth ack or anything after it.
	readErr := make(chan error, 1)
	go func() {
		_, err := ch.ReadBytes()
		readErr <- err
	}()
	select {
	case err := <-readErr:
		a.Error(err, "expected error after wrong PSK, got nil")
	case <-time.After(2 * time.Second):
		a.FailNow("no error after wrong PSK (relay should have closed)")
	}
}

// TestRelay_Auth_Missing verifies that if a password is required and
// the client does not send an Auth frame, the relay closes the
// connection.
func TestRelay_Auth_Missing(t *testing.T) {
	a := require.New(t)
	hub := newTestHub(t, "required", 0)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	stop := runServer(hub, server, nil)
	defer stop()

	// Initiate HPKE then send a Register frame without an auth frame.
	ch, err := exchange.Initiate(newRawTCPAdapter(client, 0))
	a.NoError(err, "Initiate")
	defer ch.Close()

	reg := &pb.Frame{Kind: &pb.Frame_Register{Register: &pb.Register{}}}
	b, _ := proto.Marshal(reg)
	a.NoError(ch.WriteBytes(b), "write register")

	// The relay closes the connection.
	readErr := make(chan error, 1)
	go func() {
		_, err := ch.ReadBytes()
		readErr <- err
	}()
	select {
	case err := <-readErr:
		a.Error(err, "expected error when auth missing, got nil")
	case <-time.After(2 * time.Second):
		a.FailNow("relay did not close on missing auth")
	}
}

// TestRelay_Auth_NotRequired verifies that an Auth frame sent when
// auth is not required causes the relay to close the connection.
func TestRelay_Auth_NotRequired(t *testing.T) {
	a := require.New(t)
	hub := newTestHub(t, "", 0)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	stop := runServer(hub, server, nil)
	defer stop()

	ch, err := exchange.Initiate(newRawTCPAdapter(client, 0))
	a.NoError(err, "Initiate")
	defer ch.Close()

	auth := &pb.Frame{
		Kind: &pb.Frame_Auth{Auth: &pb.Auth{Psk: []byte("anything")}},
	}
	b, _ := proto.Marshal(auth)
	a.NoError(ch.WriteBytes(b), "write auth")

	readErr := make(chan error, 1)
	go func() {
		_, err := ch.ReadBytes()
		readErr <- err
	}()
	select {
	case err := <-readErr:
		a.Error(err, "expected error when auth not required, got nil")
	case <-time.After(2 * time.Second):
		a.FailNow("relay did not close on extra auth frame")
	}
}

// TestRelay_BadRegisterFrame verifies that a non-Register frame after
// the handshake causes the relay to close the connection.
func TestRelay_BadRegisterFrame(t *testing.T) {
	a := require.New(t)
	hub := newTestHub(t, "", 0)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	stop := runServer(hub, server, nil)
	defer stop()

	ch, err := exchange.Initiate(newRawTCPAdapter(client, 0))
	a.NoError(err, "Initiate")
	defer ch.Close()

	// Send a Ping frame (not a Register).
	ping := &pb.Frame{Kind: &pb.Frame_Ping{Ping: &pb.Ping{}}}
	b, _ := proto.Marshal(ping)
	a.NoError(ch.WriteBytes(b), "write ping")

	readErr := make(chan error, 1)
	go func() {
		_, err := ch.ReadBytes()
		readErr <- err
	}()
	select {
	case err := <-readErr:
		a.Error(err, "expected error on non-Register frame, got nil")
	case <-time.After(2 * time.Second):
		a.FailNow("relay did not close on non-Register frame")
	}
}

// TestRelay_BadProtoFrame verifies that a non-protobuf frame causes
// the relay to close the connection.
func TestRelay_BadProtoFrame(t *testing.T) {
	a := require.New(t)
	hub := newTestHub(t, "", 0)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	stop := runServer(hub, server, nil)
	defer stop()

	ch, err := exchange.Initiate(newRawTCPAdapter(client, 0))
	a.NoError(err, "Initiate")
	defer ch.Close()

	a.NoError(ch.WriteBytes([]byte("not a valid protobuf")), "write garbage")

	readErr := make(chan error, 1)
	go func() {
		_, err := ch.ReadBytes()
		readErr <- err
	}()
	select {
	case err := <-readErr:
		a.Error(err, "expected error on garbage frame, got nil")
	case <-time.After(2 * time.Second):
		a.FailNow("relay did not close on garbage frame")
	}
}

// TestRelay_PingPong verifies the in-band ping/pong is handled by the
// relay's read pump.
func TestRelay_PingPong(t *testing.T) {
	a := require.New(t)
	hub := newTestHub(t, "", 0)

	listenerClient, listenerServer := net.Pipe()
	defer listenerClient.Close()
	defer listenerServer.Close()

	stop := runServer(hub, listenerServer, nil)
	defer stop()

	listenerCh, _ := dialClient(t, listenerClient, "", "", pb.Register_MODE_CREATE, nil)

	// Send a Ping; expect a Pong.
	ping := &pb.Frame{Kind: &pb.Frame_Ping{Ping: &pb.Ping{}}}
	sendFrame(t, listenerCh, ping)

	got := readFrame(t, listenerCh)
	a.NotNil(got.GetPong(), "expected Pong, got %T", got.Kind)
}

// panickingRW is a ReadWriter whose first ReadBytes call panics. It is
// used to verify that handleRelayConn recovers and cleans up the
// underlying connection.
type panickingRW struct {
	conn net.Conn
}

func (p *panickingRW) ReadBytes() ([]byte, error) {
	panic("intentional panic from panickingRW")
}

func (p *panickingRW) WriteBytes([]byte) error { return nil }
func (p *panickingRW) Close() error            { return p.conn.Close() }
func (p *panickingRW) SetDeadline(time.Time) error {
	return p.conn.SetDeadline(time.Time{})
}

// TestRelay_PanicRecovery verifies that a panic during the handshake
// (before the exchange.Channel is constructed) is recovered, the
// underlying connection is closed, and the goroutine returns normally.
func TestRelay_PanicRecovery(t *testing.T) {
	a := require.New(t)
	hub := newTestHub(t, "", 0)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// runServer uses runServer-style plumbing but with a custom adapter.
	// We invoke handleRelayConn directly with a panicking ReadWriter.
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleRelayConn(hub, &panickingRW{conn: server}, "test", nil)
	}()

	// The other end of the pipe should see the connection close shortly
	// because the defer in handleRelayConn closes the adapter.
	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, err := client.Read(buf)
		readErr <- err
	}()

	select {
	case err := <-readErr:
		a.Error(err, "client read returned nil, expected connection close")
	case <-time.After(2 * time.Second):
		a.FailNow("client read did not return (panic recovery should have closed the conn)")
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		a.FailNow("handleRelayConn did not return (panic should be recovered)")
	}
}

// --- Register dispatch (mode-based) ---------------------------------------

// makeStaticToken returns a deterministic 16-byte token.
func makeStaticToken(seed byte) []byte {
	tok := make([]byte, 32)
	for i := range tok {
		tok[i] = seed + byte(i)
	}
	return tok
}

func TestHandler_StaticToken_AcceptsProvided(t *testing.T) {
	a := require.New(t)
	hub := newTestHub(t, "", 0)

	listenerClient, listenerServer := net.Pipe()
	defer listenerClient.Close()
	defer listenerServer.Close()
	dialerClient, dialerServer := net.Pipe()
	defer dialerClient.Close()
	defer dialerServer.Close()

	stopListener := runServer(hub, listenerServer, nil)
	stopDialer := runServer(hub, dialerServer, nil)

	token := makeStaticToken(0x20)

	// Listener registers with the precomputed token; the relay must
	// echo the same token back in Registered.
	listenerCh, reg := dialClient(
		t, listenerClient, "", "",
		pb.Register_MODE_CREATE, token,
	)
	a.Equal(token, reg.GetToken(), "echoed token")

	// Dialer joins with the same token.
	dialerCh, _ := dialClient(
		t, dialerClient, "", "",
		pb.Register_MODE_JOIN, token,
	)

	// Exchange bytes both ways.
	want := []byte("hello from listener")
	sendFrame(t, listenerCh, &pb.Frame{
		Kind: &pb.Frame_Msg{Msg: &pb.Message{Data: want}},
	})
	got := readFrame(t, dialerCh)
	a.NotNil(got.GetMsg(), "expected Msg frame, got %T", got.Kind)
	a.Equal(want, got.GetMsg().GetData())

	want2 := []byte("hello from dialer")
	sendFrame(t, dialerCh, &pb.Frame{
		Kind: &pb.Frame_Msg{Msg: &pb.Message{Data: want2}},
	})
	got2 := readFrame(t, listenerCh)
	a.NotNil(got2.GetMsg(), "expected Msg frame, got %T", got2.Kind)
	a.Equal(want2, got2.GetMsg().GetData())

	stopListener()
	stopDialer()
}

func TestHandler_RejectsModeUnspecified(t *testing.T) {
	a := require.New(t)
	hub := newTestHub(t, "", 0)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	stop := runServer(hub, server, nil)
	defer stop()

	ch, err := exchange.Initiate(newRawTCPAdapter(client, 0))
	a.NoError(err, "Initiate")
	defer ch.Close()

	reg := &pb.Frame{
		Kind: &pb.Frame_Register{Register: &pb.Register{
			Mode:  pb.Register_MODE_UNSPECIFIED,
			Token: makeStaticToken(0x30),
		}},
	}
	b, _ := proto.Marshal(reg)
	a.NoError(ch.WriteBytes(b), "write register")

	readErr := make(chan error, 1)
	go func() {
		_, err := ch.ReadBytes()
		readErr <- err
	}()
	select {
	case err := <-readErr:
		a.Error(err, "expected error on MODE_UNSPECIFIED, got nil")
	case <-time.After(2 * time.Second):
		a.FailNow("relay did not close on MODE_UNSPECIFIED")
	}
}

func TestHandler_RejectsJoinWithoutToken(t *testing.T) {
	a := require.New(t)
	hub := newTestHub(t, "", 0)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	stop := runServer(hub, server, nil)
	defer stop()

	ch, err := exchange.Initiate(newRawTCPAdapter(client, 0))
	a.NoError(err, "Initiate")
	defer ch.Close()

	reg := &pb.Frame{
		Kind: &pb.Frame_Register{Register: &pb.Register{
			Mode:  pb.Register_MODE_JOIN,
			Token: nil,
		}},
	}
	b, _ := proto.Marshal(reg)
	a.NoError(ch.WriteBytes(b), "write register")

	readErr := make(chan error, 1)
	go func() {
		_, err := ch.ReadBytes()
		readErr <- err
	}()
	select {
	case err := <-readErr:
		a.Error(err, "expected error on MODE_JOIN without token, got nil")
	case <-time.After(2 * time.Second):
		a.FailNow("relay did not close on MODE_JOIN without token")
	}
}

func TestHandler_RandomTokenStillWorks(t *testing.T) {
	a := require.New(t)
	hub := newTestHub(t, "", 0)

	listenerClient, listenerServer := net.Pipe()
	defer listenerClient.Close()
	defer listenerServer.Close()
	dialerClient, dialerServer := net.Pipe()
	defer dialerClient.Close()
	defer dialerServer.Close()

	stopListener := runServer(hub, listenerServer, nil)
	stopDialer := runServer(hub, dialerServer, nil)

	// Listener: MODE_CREATE with empty token → relay generates random.
	listenerCh, reg := dialClient(
		t, listenerClient, "", "",
		pb.Register_MODE_CREATE, nil,
	)
	token := reg.GetToken()
	a.Len(token, 16)

	// Dialer: MODE_JOIN with the relay-generated token.
	dialerCh, _ := dialClient(
		t, dialerClient, "", "",
		pb.Register_MODE_JOIN, token,
	)

	want := []byte("hello")
	sendFrame(t, listenerCh, &pb.Frame{
		Kind: &pb.Frame_Msg{Msg: &pb.Message{Data: want}},
	})
	got := readFrame(t, dialerCh)
	a.NotNil(got.GetMsg(), "expected Msg frame, got %T", got.Kind)
	a.Equal(want, got.GetMsg().GetData())

	stopListener()
	stopDialer()
}

func TestHandler_RejectsWrongSizeToken(t *testing.T) {
	a := require.New(t)
	hub := newTestHub(t, "", 0)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	stop := runServer(hub, server, nil)
	defer stop()

	ch, err := exchange.Initiate(newRawTCPAdapter(client, 0))
	a.NoError(err, "Initiate")
	defer ch.Close()

	// 15-byte token (one short).
	reg := &pb.Frame{
		Kind: &pb.Frame_Register{Register: &pb.Register{
			Mode:  pb.Register_MODE_CREATE,
			Token: make([]byte, 15),
		}},
	}
	b, _ := proto.Marshal(reg)
	a.NoError(ch.WriteBytes(b), "write register")

	readErr := make(chan error, 1)
	go func() {
		_, err := ch.ReadBytes()
		readErr <- err
	}()
	select {
	case err := <-readErr:
		a.Error(err, "expected error on wrong-size token, got nil")
	case <-time.After(2 * time.Second):
		a.FailNow("relay did not close on wrong-size token")
	}
}
