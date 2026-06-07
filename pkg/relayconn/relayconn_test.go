package relayconn

import (
	"context"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/relayconn/pb"
	"google.golang.org/protobuf/proto"
)

// relayListen simulates a relay server for a listener handshake.
// Errors are sent to errCh (buffered 1).
func relayListen(
	conn net.Conn,
	password string,
	respToken []byte,
	ttlSec uint32,
	errCh chan<- error,
) {
	rw := &tcpAdapter{conn: conn}
	ch, err := exchange.Accept(rw)
	if err != nil {
		errCh <- err
		return
	}
	defer ch.Close()

	if password != "" {
		data, err := ch.ReadBytes()
		if err != nil {
			errCh <- err
			return
		}
		var f pb.Frame
		if err := proto.Unmarshal(data, &f); err != nil {
			errCh <- err
			return
		}
		if f.GetAuth() == nil {
			errCh <- net.ErrClosed
			return
		}
		auth := &pb.Frame{Kind: &pb.Frame_Auth{Auth: &pb.Auth{Psk: []byte(password)}}}
		b, _ := proto.Marshal(auth)
		if err := ch.WriteBytes(b); err != nil {
			errCh <- err
			return
		}
	}

	data, err := ch.ReadBytes()
	if err != nil {
		errCh <- err
		return
	}
	var f pb.Frame
	if err := proto.Unmarshal(data, &f); err != nil {
		errCh <- err
		return
	}
	if f.GetRegister() == nil {
		errCh <- net.ErrClosed
		return
	}

	registered := &pb.Frame{
		Kind: &pb.Frame_Registered{
			Registered: &pb.Registered{Token: respToken, TtlSeconds: ttlSec},
		},
	}
	b, _ := proto.Marshal(registered)
	errCh <- ch.WriteBytes(b)
}

// relayDial simulates a relay server for a dial handshake.
func relayDial(conn net.Conn, errCh chan<- error) {
	rw := &tcpAdapter{conn: conn}
	ch, err := exchange.Accept(rw)
	if err != nil {
		errCh <- err
		return
	}
	defer ch.Close()

	data, err := ch.ReadBytes()
	if err != nil {
		errCh <- err
		return
	}
	var f pb.Frame
	if err := proto.Unmarshal(data, &f); err != nil {
		errCh <- err
		return
	}

	registered := &pb.Frame{
		Kind: &pb.Frame_Registered{
			Registered: &pb.Registered{Token: f.GetRegister().GetToken()},
		},
	}
	b, _ := proto.Marshal(registered)
	errCh <- ch.WriteBytes(b)
}

// --- Handshake tests ---

func TestListenHandshake_Success(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	errCh := make(chan error, 1)
	go relayListen(s, "", []byte("test-token"), 300, errCh)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	listener, token, ttl, err := listenHandshake(ctx, &tcpAdapter{conn: c}, func() { c.Close() })
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	if err := <-errCh; err != nil {
		t.Fatal("relay side:", err)
	}
	if string(token) != "test-token" {
		t.Errorf("token = %q, want %q", token, "test-token")
	}
	if ttl != 5*time.Minute {
		t.Errorf("ttl = %v, want %v", ttl, 5*time.Minute)
	}
	if listener.TTL() != 5*time.Minute {
		t.Errorf("TTL() = %v, want %v", listener.TTL(), 5*time.Minute)
	}
}

func TestListenHandshake_EmptyToken(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	errCh := make(chan error, 1)
	go relayListen(s, "", nil, 0, errCh)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, _, _, err := listenHandshake(ctx, &tcpAdapter{conn: c}, func() { c.Close() })
	if err == nil || err.Error() != "relay returned empty token" {
		t.Fatalf("expected 'relay returned empty token', got %v", err)
	}
	<-errCh // drain relay error (expected)
}

func TestListenHandshake_BadUnmarshal(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	go func() {
		rw := &tcpAdapter{conn: s}
		ch, err := exchange.Accept(rw)
		if err != nil {
			t.Errorf("exchange.Accept: %v", err)
			return
		}
		defer ch.Close()
		// Read and discard Register
		ch.ReadBytes()
		// Send garbage
		ch.WriteBytes([]byte("not a valid protobuf"))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, _, _, err := listenHandshake(ctx, &tcpAdapter{conn: c}, func() { c.Close() })
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestListenHandshake_WithAuth(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	errCh := make(chan error, 1)
	go relayListen(s, "sekret", []byte("auth-token"), 60, errCh)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	listener, token, ttl, err := listenHandshake(ctx, &tcpAdapter{conn: c}, func() { c.Close() }, WithPassword("sekret"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	if err := <-errCh; err != nil {
		t.Fatal("relay side:", err)
	}
	if string(token) != "auth-token" {
		t.Errorf("token = %q, want %q", token, "auth-token")
	}
	if ttl != time.Minute {
		t.Errorf("ttl = %v, want %v", ttl, time.Minute)
	}
}

func TestDialHandshake_Success(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	errCh := make(chan error, 1)
	go relayDial(s, errCh)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rc, err := relayHandshake(ctx, &tcpAdapter{conn: c}, []byte("dial-token"), func() { c.Close() })
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()

	if err := <-errCh; err != nil {
		t.Fatal("relay side:", err)
	}
}

func TestDialHandshake_WrongFrame(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	go func() {
		rw := &tcpAdapter{conn: s}
		ch, err := exchange.Accept(rw)
		if err != nil {
			t.Errorf("exchange.Accept: %v", err)
			return
		}
		defer ch.Close()
		ch.ReadBytes() // discard Register
		// Send unexpected Ping instead of Registered
		ping := &pb.Frame{Kind: &pb.Frame_Ping{Ping: &pb.Ping{}}}
		b, _ := proto.Marshal(ping)
		ch.WriteBytes(b)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := relayHandshake(ctx, &tcpAdapter{conn: c}, []byte("t"), func() { c.Close() })
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// --- Listener lifecycle ---

func TestListenAccept_AfterStop(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	errCh := make(chan error, 1)
	go relayListen(s, "", []byte("l"), 300, errCh)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	l, _, _, err := listenHandshake(ctx, &tcpAdapter{conn: c}, func() { c.Close() })
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	<-errCh

	l.Stop()
	_, err = l.Accept()
	if err != net.ErrClosed {
		t.Fatalf("Accept() after Stop: got %v, want net.ErrClosed", err)
	}
}

func TestListenAccept_AfterClose(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	errCh := make(chan error, 1)
	go relayListen(s, "", []byte("l"), 300, errCh)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	l, _, _, err := listenHandshake(ctx, &tcpAdapter{conn: c}, func() { c.Close() })
	if err != nil {
		t.Fatal(err)
	}
	<-errCh

	l.Close()
	_, err = l.Accept()
	if err != net.ErrClosed {
		t.Fatalf("Accept() after Close: got %v, want net.ErrClosed", err)
	}
}

// --- RelayConn ---

func TestRelayConnWriteRead(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	// Establish exchange channel pair
	var (
		serverCh *exchange.Channel
		serverOK = make(chan error, 1)
	)
	go func() {
		ch, err := exchange.Accept(&tcpAdapter{conn: s})
		if err != nil {
			serverOK <- err
			return
		}
		serverCh = ch
		serverOK <- err
	}()

	clientCh, err := exchange.Initiate(&tcpAdapter{conn: c})
	if err != nil {
		t.Fatal("Initiate:", err)
	}
	defer clientCh.Close()
	if err := <-serverOK; err != nil {
		t.Fatal("Accept:", err)
	}
	defer serverCh.Close()

	// Create RelayConn on client side. readPump starts later to avoid pipe
	// contention (net.Pipe requires concurrent read/write).
	var mu sync.Mutex
	ctx, connCancel := context.WithCancel(context.Background())
	defer connCancel()
	rc := newRelayConn(ctx, clientCh, &mu)
	rc.closeFn = func() { clientCh.Close() }
	defer rc.Close()

	// Client writes, relay reads concurrently (net.Pipe is unbuffered)
	serverGot := make(chan []byte, 1)
	go func() {
		data, err := serverCh.ReadBytes()
		if err != nil {
			t.Error("serverCh.ReadBytes:", err)
			return
		}
		serverGot <- data
	}()

	if err := rc.WriteBytes([]byte("hello")); err != nil {
		t.Fatal("WriteBytes:", err)
	}

	got := <-serverGot
	var frame pb.Frame
	if err := proto.Unmarshal(got, &frame); err != nil {
		t.Fatal("unmarshal:", err)
	}
	if string(frame.GetMsg().GetData()) != "hello" {
		t.Errorf("got %q, want %q", frame.GetMsg().GetData(), "hello")
	}

	// Now start readPump for the read-back direction
	go rc.readPump()

	// Relay writes, client reads
	resp := &pb.Frame{
		Kind: &pb.Frame_Msg{
			Msg: &pb.Message{Data: []byte("world")},
		},
	}
	b, _ := proto.Marshal(resp)
	if err := serverCh.WriteBytes(b); err != nil {
		t.Fatal("server WriteBytes:", err)
	}
	got2, err := rc.ReadBytes()
	if err != nil {
		t.Fatal("rc ReadBytes:", err)
	}
	if string(got2) != "world" {
		t.Errorf("got %q, want %q", got2, "world")
	}
}

func TestRelayConnDeadline(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	// Establish exchange channel pair
	var (
		serverCh *exchange.Channel
		serverOK = make(chan error, 1)
	)
	go func() {
		ch, err := exchange.Accept(&tcpAdapter{conn: s})
		if err != nil {
			serverOK <- err
			return
		}
		serverCh = ch
		serverOK <- err
	}()
	clientCh, err := exchange.Initiate(&tcpAdapter{conn: c})
	if err != nil {
		t.Fatal("Initiate:", err)
	}
	defer clientCh.Close()
	if err := <-serverOK; err != nil {
		t.Fatal("Accept:", err)
	}
	defer serverCh.Close()

	var mu sync.Mutex
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rc := newRelayConn(ctx, clientCh, &mu)
	rc.closeFn = func() { clientCh.Close() }
	go rc.readPump()
	defer rc.Close()

	// Set deadline in the past → immediate timeout
	rc.SetDeadline(time.Now().Add(-time.Second))
	_, err = rc.ReadBytes()
	if err != os.ErrDeadlineExceeded {
		t.Fatalf("got %v, want os.ErrDeadlineExceeded", err)
	}
}

func TestRelayConnCloseIdempotent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rc := newRelayConn(ctx, nil, nil)

	rc.Close()
	rc.Close() // second close must not panic
}

// --- Transport ---

func TestTcpAdapterLengthPrefix(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	go func() {
		adapter := &tcpAdapter{conn: s}
		data, err := adapter.ReadBytes()
		if err != nil {
			t.Errorf("ReadBytes: %v", err)
			return
		}
		if string(data) != "hello" {
			t.Errorf("got %q, want %q", data, "hello")
		}
		adapter.WriteBytes([]byte("world"))
	}()

	adapter := &tcpAdapter{conn: c}
	if err := adapter.WriteBytes([]byte("hello")); err != nil {
		t.Fatal("WriteBytes:", err)
	}
	data, err := adapter.ReadBytes()
	if err != nil {
		t.Fatal("ReadBytes:", err)
	}
	if string(data) != "world" {
		t.Errorf("got %q, want %q", data, "world")
	}
}
