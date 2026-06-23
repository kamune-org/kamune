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
func newTestHub(t *testing.T, password string, handshakeTimeout time.Duration) *services.Hub {
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
	token []byte,
) (*exchange.Channel, *pb.Registered) {
	t.Helper()
	ch, err := exchange.Initiate(&rawTCPAdapter{conn: conn, maxSize: 0})
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
		Kind: &pb.Frame_Register{Register: &pb.Register{Token: token}},
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
		adapter := &rawTCPAdapter{conn: conn, maxSize: hub.MaxMessageSize()}
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
	listenerCh, reg := dialClient(t, listenerClient, "", "", nil)
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
	dialerCh, _ := dialClient(t, dialerClient, "", "", token)

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

	listenerCh, reg := dialClient(t, listenerClient, "", "", nil)
	token := reg.GetToken()
	dialerCh, _ := dialClient(t, dialerClient, "", "", token)

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

	ch, reg := dialClient(t, client, password, password, nil)
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
	ch, err := exchange.Initiate(&rawTCPAdapter{conn: client, maxSize: 0})
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
	ch, err := exchange.Initiate(&rawTCPAdapter{conn: client, maxSize: 0})
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

	ch, err := exchange.Initiate(&rawTCPAdapter{conn: client, maxSize: 0})
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

	ch, err := exchange.Initiate(&rawTCPAdapter{conn: client, maxSize: 0})
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

	ch, err := exchange.Initiate(&rawTCPAdapter{conn: client, maxSize: 0})
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

	listenerCh, _ := dialClient(t, listenerClient, "", "", nil)

	// Send a Ping; expect a Pong.
	ping := &pb.Frame{Kind: &pb.Frame_Ping{Ping: &pb.Ping{}}}
	sendFrame(t, listenerCh, ping)

	got := readFrame(t, listenerCh)
	if got.GetPong() == nil {
		t.Fatalf("expected Pong, got %T", got.Kind)
	}
}

// Ensure we don't accidentally rely on a real ctx that would cancel
// before the test can run; the package import is here as a marker.
