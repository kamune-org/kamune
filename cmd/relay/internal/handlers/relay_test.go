package handlers

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/relayconn/pb"
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
	ch, err := exchange.Initiate(newRawTCPAdapter(conn, 0))
	if err != nil {
		t.Fatalf("Initiate: %v", err)
	}

	if password != "" {
		if authPassword == "" {
			t.Fatalf("dialClient: password required but authPassword empty")
		}
		auth := &pb.Frame{
			Kind: &pb.Frame_Auth{Auth: &pb.Auth{Psk: []byte(authPassword)}},
		}
		b, err := proto.Marshal(auth)
		if err != nil {
			t.Fatalf("marshal auth: %v", err)
		}
		if err := ch.WriteBytes(b); err != nil {
			t.Fatalf("write auth: %v", err)
		}
		// Drain the ack.
		if _, err := ch.ReadBytes(); err != nil {
			t.Fatalf("read auth ack: %v", err)
		}
	}

	reg := &pb.Frame{
		Kind: &pb.Frame_Register{Register: &pb.Register{
			Mode:  mode,
			Token: token,
		}},
	}
	b, err := proto.Marshal(reg)
	if err != nil {
		t.Fatalf("marshal register: %v", err)
	}
	if err := ch.WriteBytes(b); err != nil {
		t.Fatalf("write register: %v", err)
	}

	resp, err := ch.ReadBytes()
	if err != nil {
		t.Fatalf("read registered: %v", err)
	}
	var f pb.Frame
	if err := proto.Unmarshal(resp, &f); err != nil {
		t.Fatalf("unmarshal registered: %v", err)
	}
	reg2 := f.GetRegistered()
	if reg2 == nil {
		t.Fatalf("expected Registered frame, got %T", f.Kind)
	}
	return ch, reg2
}

// sendFrame marshals and writes a Frame over the exchange channel.
func sendFrame(t *testing.T, ch *exchange.Channel, f *pb.Frame) {
	t.Helper()
	b, err := proto.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := ch.WriteBytes(b); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// readFrame reads a single Frame from the channel.
func readFrame(t *testing.T, ch *exchange.Channel) *pb.Frame {
	t.Helper()
	b, err := ch.ReadBytes()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var f pb.Frame
	if err := proto.Unmarshal(b, &f); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
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
	if got := reg.GetTtlSeconds(); got == 0 {
		t.Errorf("TtlSeconds = 0, want > 0")
	}
	token := reg.GetToken()
	if len(token) != 16 {
		t.Errorf("token length = %d, want 16", len(token))
	}

	// Timer should be stopped after handshake completes.
	time.Sleep(20 * time.Millisecond)
	if listenerTimer.Stop() {
		t.Error("listenerTimer was not stopped after registration")
	}

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
	if msg := got.GetMsg(); msg == nil {
		t.Fatalf("expected Msg frame, got %T", got.Kind)
	} else if !bytes.Equal(msg.GetData(), want) {
		t.Errorf("payload = %q, want %q", msg.GetData(), want)
	}

	// And dialer → listener.
	want2 := []byte("hello from dialer")
	sendFrame(t, dialerCh, &pb.Frame{
		Kind: &pb.Frame_Msg{Msg: &pb.Message{Data: want2}},
	})
	got2 := readFrame(t, listenerCh)
	if msg := got2.GetMsg(); msg == nil {
		t.Fatalf("expected Msg frame, got %T", got2.Kind)
	} else if !bytes.Equal(msg.GetData(), want2) {
		t.Errorf("payload = %q, want %q", msg.GetData(), want2)
	}

	stopListener()
	stopDialer()
}

// TestRelay_Disconnect_ClosesPeer ensures that closing one peer's
// underlying connection causes the other peer's channel to close
// (via ClosePeerChannel) and ReadPump to exit.
func TestRelay_Disconnect_ClosesPeer(t *testing.T) {
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
		if err == nil {
			t.Error("listener ReadBytes returned nil after peer disconnect")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("listener ReadBytes did not return after peer disconnect")
	}

	_ = listenerClient.Close()
	_ = listenerServer.Close()
}

// TestRelay_Auth_Required exercises the password path end-to-end.
func TestRelay_Auth_Required(t *testing.T) {
	const password = "s3kret"
	hub := newTestHub(t, password, 0)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	stop := runServer(hub, server, nil)
	defer stop()

	ch, reg := dialClient(t, client, password, password, pb.Register_MODE_CREATE, nil)
	if reg == nil {
		t.Fatal("Registered is nil")
	}
	_ = ch.Close()
}

// TestRelay_Auth_WrongPSK verifies that a wrong password causes the
// relay to close the connection (we expect a read error from the
// client's side).
func TestRelay_Auth_WrongPSK(t *testing.T) {
	hub := newTestHub(t, "right", 0)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	stop := runServer(hub, server, nil)
	defer stop()

	// The client does HPKE Initiate, then sends auth with wrong PSK.
	// The server should close before we ever see a Registered frame.
	ch, err := exchange.Initiate(newRawTCPAdapter(client, 0))
	if err != nil {
		t.Fatalf("Initiate: %v", err)
	}
	defer ch.Close()

	auth := &pb.Frame{
		Kind: &pb.Frame_Auth{Auth: &pb.Auth{Psk: []byte("wrong")}},
	}
	b, _ := proto.Marshal(auth)
	if err := ch.WriteBytes(b); err != nil {
		t.Fatalf("write auth: %v", err)
	}

	// The relay closes the connection. We expect an error reading
	// either the auth ack or anything after it.
	readErr := make(chan error, 1)
	go func() {
		_, err := ch.ReadBytes()
		readErr <- err
	}()
	select {
	case err := <-readErr:
		if err == nil {
			t.Error("expected error after wrong PSK, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no error after wrong PSK (relay should have closed)")
	}
}

// TestRelay_Auth_Missing verifies that if a password is required and
// the client does not send an Auth frame, the relay closes the
// connection.
func TestRelay_Auth_Missing(t *testing.T) {
	hub := newTestHub(t, "required", 0)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	stop := runServer(hub, server, nil)
	defer stop()

	// Initiate HPKE then send a Register frame without an auth frame.
	ch, err := exchange.Initiate(newRawTCPAdapter(client, 0))
	if err != nil {
		t.Fatalf("Initiate: %v", err)
	}
	defer ch.Close()

	reg := &pb.Frame{Kind: &pb.Frame_Register{Register: &pb.Register{}}}
	b, _ := proto.Marshal(reg)
	if err := ch.WriteBytes(b); err != nil {
		t.Fatalf("write register: %v", err)
	}

	// The relay closes the connection.
	readErr := make(chan error, 1)
	go func() {
		_, err := ch.ReadBytes()
		readErr <- err
	}()
	select {
	case err := <-readErr:
		if err == nil {
			t.Error("expected error when auth missing, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not close on missing auth")
	}
}

// TestRelay_Auth_NotRequired verifies that an Auth frame sent when
// auth is not required causes the relay to close the connection.
func TestRelay_Auth_NotRequired(t *testing.T) {
	hub := newTestHub(t, "", 0)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	stop := runServer(hub, server, nil)
	defer stop()

	ch, err := exchange.Initiate(newRawTCPAdapter(client, 0))
	if err != nil {
		t.Fatalf("Initiate: %v", err)
	}
	defer ch.Close()

	auth := &pb.Frame{
		Kind: &pb.Frame_Auth{Auth: &pb.Auth{Psk: []byte("anything")}},
	}
	b, _ := proto.Marshal(auth)
	if err := ch.WriteBytes(b); err != nil {
		t.Fatalf("write auth: %v", err)
	}

	readErr := make(chan error, 1)
	go func() {
		_, err := ch.ReadBytes()
		readErr <- err
	}()
	select {
	case err := <-readErr:
		if err == nil {
			t.Error("expected error when auth not required, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not close on extra auth frame")
	}
}

// TestRelay_BadRegisterFrame verifies that a non-Register frame after
// the handshake causes the relay to close the connection.
func TestRelay_BadRegisterFrame(t *testing.T) {
	hub := newTestHub(t, "", 0)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	stop := runServer(hub, server, nil)
	defer stop()

	ch, err := exchange.Initiate(newRawTCPAdapter(client, 0))
	if err != nil {
		t.Fatalf("Initiate: %v", err)
	}
	defer ch.Close()

	// Send a Ping frame (not a Register).
	ping := &pb.Frame{Kind: &pb.Frame_Ping{Ping: &pb.Ping{}}}
	b, _ := proto.Marshal(ping)
	if err := ch.WriteBytes(b); err != nil {
		t.Fatalf("write ping: %v", err)
	}

	readErr := make(chan error, 1)
	go func() {
		_, err := ch.ReadBytes()
		readErr <- err
	}()
	select {
	case err := <-readErr:
		if err == nil {
			t.Error("expected error on non-Register frame, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not close on non-Register frame")
	}
}

// TestRelay_BadProtoFrame verifies that a non-protobuf frame causes
// the relay to close the connection.
func TestRelay_BadProtoFrame(t *testing.T) {
	hub := newTestHub(t, "", 0)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	stop := runServer(hub, server, nil)
	defer stop()

	ch, err := exchange.Initiate(newRawTCPAdapter(client, 0))
	if err != nil {
		t.Fatalf("Initiate: %v", err)
	}
	defer ch.Close()

	if err := ch.WriteBytes([]byte("not a valid protobuf")); err != nil {
		t.Fatalf("write garbage: %v", err)
	}

	readErr := make(chan error, 1)
	go func() {
		_, err := ch.ReadBytes()
		readErr <- err
	}()
	select {
	case err := <-readErr:
		if err == nil {
			t.Error("expected error on garbage frame, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not close on garbage frame")
	}
}

// TestRelay_PingPong verifies the in-band ping/pong is handled by the
// relay's read pump.
func TestRelay_PingPong(t *testing.T) {
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
	if got.GetPong() == nil {
		t.Fatalf("expected Pong, got %T", got.Kind)
	}
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
		if err == nil {
			t.Error("client read returned nil, expected connection close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("client read did not return (panic recovery should have closed the conn)")
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleRelayConn did not return (panic should be recovered)")
	}
}

// --- Register dispatch (mode-based) ---------------------------------------

// makeStaticToken returns a deterministic 16-byte token.
func makeStaticToken(seed byte) []byte {
	tok := make([]byte, 16)
	for i := range tok {
		tok[i] = seed + byte(i)
	}
	return tok
}

func TestHandler_StaticToken_AcceptsProvided(t *testing.T) {
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
	if got := reg.GetToken(); !bytes.Equal(got, token) {
		t.Errorf("echoed token = %x, want %x", got, token)
	}

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
	if msg := got.GetMsg(); msg == nil {
		t.Fatalf("expected Msg frame, got %T", got.Kind)
	} else if !bytes.Equal(msg.GetData(), want) {
		t.Errorf("payload = %q, want %q", msg.GetData(), want)
	}

	want2 := []byte("hello from dialer")
	sendFrame(t, dialerCh, &pb.Frame{
		Kind: &pb.Frame_Msg{Msg: &pb.Message{Data: want2}},
	})
	got2 := readFrame(t, listenerCh)
	if msg := got2.GetMsg(); msg == nil {
		t.Fatalf("expected Msg frame, got %T", got2.Kind)
	} else if !bytes.Equal(msg.GetData(), want2) {
		t.Errorf("payload = %q, want %q", msg.GetData(), want2)
	}

	stopListener()
	stopDialer()
}

func TestHandler_RejectsModeUnspecified(t *testing.T) {
	hub := newTestHub(t, "", 0)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	stop := runServer(hub, server, nil)
	defer stop()

	ch, err := exchange.Initiate(newRawTCPAdapter(client, 0))
	if err != nil {
		t.Fatalf("Initiate: %v", err)
	}
	defer ch.Close()

	reg := &pb.Frame{
		Kind: &pb.Frame_Register{Register: &pb.Register{
			Mode:  pb.Register_MODE_UNSPECIFIED,
			Token: makeStaticToken(0x30),
		}},
	}
	b, _ := proto.Marshal(reg)
	if err := ch.WriteBytes(b); err != nil {
		t.Fatalf("write register: %v", err)
	}

	readErr := make(chan error, 1)
	go func() {
		_, err := ch.ReadBytes()
		readErr <- err
	}()
	select {
	case err := <-readErr:
		if err == nil {
			t.Error("expected error on MODE_UNSPECIFIED, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not close on MODE_UNSPECIFIED")
	}
}

func TestHandler_RejectsJoinWithoutToken(t *testing.T) {
	hub := newTestHub(t, "", 0)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	stop := runServer(hub, server, nil)
	defer stop()

	ch, err := exchange.Initiate(newRawTCPAdapter(client, 0))
	if err != nil {
		t.Fatalf("Initiate: %v", err)
	}
	defer ch.Close()

	reg := &pb.Frame{
		Kind: &pb.Frame_Register{Register: &pb.Register{
			Mode:  pb.Register_MODE_JOIN,
			Token: nil,
		}},
	}
	b, _ := proto.Marshal(reg)
	if err := ch.WriteBytes(b); err != nil {
		t.Fatalf("write register: %v", err)
	}

	readErr := make(chan error, 1)
	go func() {
		_, err := ch.ReadBytes()
		readErr <- err
	}()
	select {
	case err := <-readErr:
		if err == nil {
			t.Error(
				"expected error on MODE_JOIN without token, got nil",
			)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not close on MODE_JOIN without token")
	}
}

func TestHandler_RandomTokenStillWorks(t *testing.T) {
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
	if len(token) != 16 {
		t.Fatalf(
			"relay-generated token length = %d, want 16",
			len(token),
		)
	}

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
	if msg := got.GetMsg(); msg == nil {
		t.Fatalf("expected Msg frame, got %T", got.Kind)
	} else if !bytes.Equal(msg.GetData(), want) {
		t.Errorf("payload = %q, want %q", msg.GetData(), want)
	}

	stopListener()
	stopDialer()
}

func TestHandler_RejectsWrongSizeToken(t *testing.T) {
	hub := newTestHub(t, "", 0)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	stop := runServer(hub, server, nil)
	defer stop()

	ch, err := exchange.Initiate(newRawTCPAdapter(client, 0))
	if err != nil {
		t.Fatalf("Initiate: %v", err)
	}
	defer ch.Close()

	// 15-byte token (one short).
	reg := &pb.Frame{
		Kind: &pb.Frame_Register{Register: &pb.Register{
			Mode:  pb.Register_MODE_CREATE,
			Token: make([]byte, 15),
		}},
	}
	b, _ := proto.Marshal(reg)
	if err := ch.WriteBytes(b); err != nil {
		t.Fatalf("write register: %v", err)
	}

	readErr := make(chan error, 1)
	go func() {
		_, err := ch.ReadBytes()
		readErr <- err
	}()
	select {
	case err := <-readErr:
		if err == nil {
			t.Error(
				"expected error on wrong-size token, got nil",
			)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not close on wrong-size token")
	}
}
