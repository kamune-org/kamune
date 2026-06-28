package relayconn

import (
	"context"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/relayconn/pb"
)

var (
	_ kamune.Conn = &RelayConn{}
	_ kamune.Conn = &tcpAdapter{}
	_ kamune.Conn = &wsAdapter{}
	_ kamune.Conn = &tlsAdapter{}
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
	rw := newTCPAdapter(conn)
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
	rw := newTCPAdapter(conn)
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

	result, err := listenHandshake(ctx, newTCPAdapter(c), func() { c.Close() })
	if err != nil {
		t.Fatal(err)
	}
	defer result.Listener.Close()

	if err := <-errCh; err != nil {
		t.Fatal("relay side:", err)
	}
	if string(result.Token) != "test-token" {
		t.Errorf("token = %q, want %q", result.Token, "test-token")
	}
	if result.TTL != 5*time.Minute {
		t.Errorf("ttl = %v, want %v", result.TTL, 5*time.Minute)
	}
	if result.Listener.TTL() != 5*time.Minute {
		t.Errorf("TTL() = %v, want %v", result.Listener.TTL(), 5*time.Minute)
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

	_, err := listenHandshake(ctx, newTCPAdapter(c), func() { c.Close() })
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
		rw := newTCPAdapter(s)
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

	_, err := listenHandshake(ctx, newTCPAdapter(c), func() { c.Close() })
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

	result, err := listenHandshake(ctx, newTCPAdapter(c), func() { c.Close() }, WithPassword("sekret"))
	if err != nil {
		t.Fatal(err)
	}
	defer result.Listener.Close()

	if err := <-errCh; err != nil {
		t.Fatal("relay side:", err)
	}
	if string(result.Token) != "auth-token" {
		t.Errorf("token = %q, want %q", result.Token, "auth-token")
	}
	if result.TTL != time.Minute {
		t.Errorf("ttl = %v, want %v", result.TTL, time.Minute)
	}
}

func TestListenHandshake_SessionTTL(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	errCh := make(chan error, 1)
	go func() {
		rw := newTCPAdapter(s)
		ch, err := exchange.Accept(rw)
		if err != nil {
			errCh <- err
			return
		}
		defer ch.Close()
		if _, err := ch.ReadBytes(); err != nil {
			errCh <- err
			return
		}
		registered := &pb.Frame{
			Kind: &pb.Frame_Registered{
				Registered: &pb.Registered{
					Token:             []byte("sttl-token"),
					TtlSeconds:        300,
					SessionTtlSeconds: 1800,
				},
			},
		}
		b, _ := proto.Marshal(registered)
		errCh <- ch.WriteBytes(b)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := listenHandshake(ctx, newTCPAdapter(c), func() { c.Close() })
	if err != nil {
		t.Fatal(err)
	}
	defer result.Listener.Close()

	if err := <-errCh; err != nil {
		t.Fatal("relay side:", err)
	}
	if string(result.Token) != "sttl-token" {
		t.Errorf("token = %q, want %q", result.Token, "sttl-token")
	}
	if result.TTL != 5*time.Minute {
		t.Errorf("TTL = %v, want %v", result.TTL, 5*time.Minute)
	}
	if result.SessionTTL != 30*time.Minute {
		t.Errorf("SessionTTL = %v, want %v", result.SessionTTL, 30*time.Minute)
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

	rc, err := relayHandshake(ctx, newTCPAdapter(c), []byte("dial-token"), func() { c.Close() })
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
		rw := newTCPAdapter(s)
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

	_, err := relayHandshake(ctx, newTCPAdapter(c), []byte("t"), func() { c.Close() })
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

	result, err := listenHandshake(ctx, newTCPAdapter(c), func() { c.Close() })
	if err != nil {
		t.Fatal(err)
	}
	defer result.Listener.Close()
	<-errCh

	result.Listener.Stop()
	_, err = result.Listener.Accept()
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

	result, err := listenHandshake(ctx, newTCPAdapter(c), func() { c.Close() })
	if err != nil {
		t.Fatal(err)
	}
	<-errCh

	result.Listener.Close()
	_, err = result.Listener.Accept()
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
		ch, err := exchange.Accept(newTCPAdapter(s))
		if err != nil {
			serverOK <- err
			return
		}
		serverCh = ch
		serverOK <- err
	}()

	clientCh, err := exchange.Initiate(newTCPAdapter(c))
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
	rc := newRelayConn(t.Context(), clientCh, &mu)
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
		ch, err := exchange.Accept(newTCPAdapter(s))
		if err != nil {
			serverOK <- err
			return
		}
		serverCh = ch
		serverOK <- err
	}()
	clientCh, err := exchange.Initiate(newTCPAdapter(c))
	if err != nil {
		t.Fatal("Initiate:", err)
	}
	defer clientCh.Close()
	if err := <-serverOK; err != nil {
		t.Fatal("Accept:", err)
	}
	defer serverCh.Close()

	var mu sync.Mutex
	rc := newRelayConn(t.Context(), clientCh, &mu)
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
	rc := newRelayConn(t.Context(), nil, nil)

	rc.Close()
	rc.Close() // second close must not panic
}

// --- Transport ---

func TestTcpAdapterLengthPrefix(t *testing.T) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	go func() {
		adapter := newTCPAdapter(s)
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

	adapter := newTCPAdapter(c)
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
