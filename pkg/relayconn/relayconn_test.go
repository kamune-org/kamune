package relayconn

import (
	"context"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/stretchr/testify/require"

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
	a := require.New(t)
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	errCh := make(chan error, 1)
	go relayListen(s, "", []byte("test-token"), 300, errCh)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := listenHandshake(ctx, newTCPAdapter(c), func() { c.Close() })
	a.NoError(err)
	defer result.Listener.Close()

	a.NoError(<-errCh)
	a.Equal("test-token", string(result.Token))
	a.Equal(5*time.Minute, result.TTL)
	a.Equal(5*time.Minute, result.Listener.TTL())
}

func TestListenHandshake_EmptyToken(t *testing.T) {
	a := require.New(t)
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	errCh := make(chan error, 1)
	go relayListen(s, "", nil, 0, errCh)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := listenHandshake(ctx, newTCPAdapter(c), func() { c.Close() })
	a.Error(err)
	a.Equal("relay returned empty token", err.Error())
	<-errCh // drain relay error (expected)
}

func TestListenHandshake_BadUnmarshal(t *testing.T) {
	a := require.New(t)
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	go func() {
		rw := newTCPAdapter(s)
		ch, err := exchange.Accept(rw)
		if err != nil {
			return
		}
		defer ch.Close()
		ch.ReadBytes()
		ch.WriteBytes([]byte("not a valid protobuf"))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := listenHandshake(ctx, newTCPAdapter(c), func() { c.Close() })
	a.Error(err)
}

func TestListenHandshake_WithAuth(t *testing.T) {
	a := require.New(t)
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	errCh := make(chan error, 1)
	go relayListen(s, "sekret", []byte("auth-token"), 60, errCh)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := listenHandshake(ctx, newTCPAdapter(c), func() { c.Close() }, WithPassword("sekret"))
	a.NoError(err)
	defer result.Listener.Close()

	a.NoError(<-errCh)
	a.Equal("auth-token", string(result.Token))
	a.Equal(time.Minute, result.TTL)
}

func TestListenHandshake_SessionTTL(t *testing.T) {
	a := require.New(t)
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
	a.NoError(err)
	defer result.Listener.Close()

	a.NoError(<-errCh)
	a.Equal("sttl-token", string(result.Token))
	a.Equal(5*time.Minute, result.TTL)
	a.Equal(30*time.Minute, result.SessionTTL)
}

func TestDialHandshake_Success(t *testing.T) {
	a := require.New(t)
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	errCh := make(chan error, 1)
	go relayDial(s, errCh)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rc, err := relayHandshake(ctx, newTCPAdapter(c), []byte("dial-token"), func() { c.Close() })
	a.NoError(err)
	defer rc.Close()

	a.NoError(<-errCh)
}

func TestDialHandshake_WrongFrame(t *testing.T) {
	a := require.New(t)
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	go func() {
		rw := newTCPAdapter(s)
		ch, err := exchange.Accept(rw)
		if err != nil {
			return
		}
		defer ch.Close()
		ch.ReadBytes()
		ping := &pb.Frame{Kind: &pb.Frame_Ping{Ping: &pb.Ping{}}}
		b, _ := proto.Marshal(ping)
		ch.WriteBytes(b)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := relayHandshake(ctx, newTCPAdapter(c), []byte("t"), func() { c.Close() })
	a.Error(err)
}

// --- Listener lifecycle ---

func TestListenAccept_AfterStop(t *testing.T) {
	a := require.New(t)
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	errCh := make(chan error, 1)
	go relayListen(s, "", []byte("l"), 300, errCh)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := listenHandshake(ctx, newTCPAdapter(c), func() { c.Close() })
	a.NoError(err)
	defer result.Listener.Close()
	<-errCh

	result.Listener.Stop()
	_, err = result.Listener.Accept()
	a.ErrorIs(err, net.ErrClosed)
}

func TestListenAccept_AfterClose(t *testing.T) {
	a := require.New(t)
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	errCh := make(chan error, 1)
	go relayListen(s, "", []byte("l"), 300, errCh)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := listenHandshake(ctx, newTCPAdapter(c), func() { c.Close() })
	a.NoError(err)
	<-errCh

	result.Listener.Close()
	_, err = result.Listener.Accept()
	a.ErrorIs(err, net.ErrClosed)
}

// --- RelayConn ---

func TestRelayConnWriteRead(t *testing.T) {
	a := require.New(t)
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

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
	a.NoError(err)
	defer clientCh.Close()
	a.NoError(<-serverOK)
	defer serverCh.Close()

	var mu sync.Mutex
	rc := newRelayConn(t.Context(), clientCh, &mu)
	rc.closeFn = func() { clientCh.Close() }
	defer rc.Close()

	serverGot := make(chan []byte, 1)
	go func() {
		data, err := serverCh.ReadBytes()
		if err != nil {
			return
		}
		serverGot <- data
	}()

	a.NoError(rc.WriteBytes([]byte("hello")))

	got := <-serverGot
	var frame pb.Frame
	a.NoError(proto.Unmarshal(got, &frame))
	a.Equal("hello", string(frame.GetMsg().GetData()))

	go rc.readPump()

	resp := &pb.Frame{
		Kind: &pb.Frame_Msg{
			Msg: &pb.Message{Data: []byte("world")},
		},
	}
	b, _ := proto.Marshal(resp)
	a.NoError(serverCh.WriteBytes(b))
	got2, err := rc.ReadBytes()
	a.NoError(err)
	a.Equal("world", string(got2))
}

func TestRelayConnDeadline(t *testing.T) {
	a := require.New(t)
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

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
	a.NoError(err)
	defer clientCh.Close()
	a.NoError(<-serverOK)
	defer serverCh.Close()

	var mu sync.Mutex
	rc := newRelayConn(t.Context(), clientCh, &mu)
	rc.closeFn = func() { clientCh.Close() }
	go rc.readPump()
	defer rc.Close()

	rc.SetDeadline(time.Now().Add(-time.Second))
	_, err = rc.ReadBytes()
	a.ErrorIs(err, os.ErrDeadlineExceeded)
}

func TestRelayConnCloseIdempotent(t *testing.T) {
	rc := newRelayConn(t.Context(), nil, nil)
	rc.Close()
	rc.Close()
}

// --- Transport ---

func TestTcpAdapterLengthPrefix(t *testing.T) {
	a := require.New(t)
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	go func() {
		adapter := newTCPAdapter(s)
		data, err := adapter.ReadBytes()
		if err != nil {
			return
		}
		adapter.WriteBytes([]byte("world"))
		_ = data
	}()

	adapter := newTCPAdapter(c)
	a.NoError(adapter.WriteBytes([]byte("hello")))
	data, err := adapter.ReadBytes()
	a.NoError(err)
	a.Equal("world", string(data))
}

// setupListener creates a listener via listenHandshake and returns the
// listener plus a server-side exchange.Channel for sending frames.
func setupListener(t *testing.T) (*RelayListener, *exchange.Channel) {
	t.Helper()
	a := require.New(t)
	c, s := net.Pipe()
	t.Cleanup(func() { c.Close(); s.Close() })

	serverReady := make(chan *exchange.Channel, 1)
	go func() {
		rw := newTCPAdapter(s)
		ch, err := exchange.Accept(rw)
		if err != nil {
			serverReady <- nil
			return
		}

		data, err := ch.ReadBytes()
		if err != nil {
			serverReady <- nil
			return
		}
		var f pb.Frame
		if err := proto.Unmarshal(data, &f); err != nil {
			serverReady <- nil
			return
		}

		registered := &pb.Frame{
			Kind: &pb.Frame_Registered{
				Registered: &pb.Registered{
					Token:      []byte("test-token"),
					TtlSeconds: 300,
				},
			},
		}
		b, _ := proto.Marshal(registered)
		if err := ch.WriteBytes(b); err != nil {
			serverReady <- nil
			return
		}
		serverReady <- ch
	}()

	ctx := t.Context()
	result, err := listenHandshake(ctx, newTCPAdapter(c), func() {
		c.Close()
	})
	a.NoError(err)
	t.Cleanup(func() { result.Listener.Close() })

	serverCh := <-serverReady
	a.NotNil(serverCh)
	t.Cleanup(func() { serverCh.Close() })

	return result.Listener, serverCh
}

func TestListenerDeliver_FirstMessage(t *testing.T) {
	a := require.New(t)
	listener, serverCh := setupListener(t)

	msg := &pb.Frame{
		Kind: &pb.Frame_Msg{
			Msg: &pb.Message{Data: []byte("hello")},
		},
	}
	b, _ := proto.Marshal(msg)
	a.NoError(serverCh.WriteBytes(b))

	conn, err := listener.Accept()
	a.NoError(err)
	defer conn.Close()

	got, err := conn.ReadBytes()
	a.NoError(err)
	a.Equal("hello", string(got))
}

func TestListenerDeliver_SecondMessage(t *testing.T) {
	a := require.New(t)
	listener, serverCh := setupListener(t)

	msg1 := &pb.Frame{Kind: &pb.Frame_Msg{Msg: &pb.Message{Data: []byte("one")}}}
	b1, _ := proto.Marshal(msg1)
	a.NoError(serverCh.WriteBytes(b1))

	conn, err := listener.Accept()
	a.NoError(err)
	defer conn.Close()

	got1, err := conn.ReadBytes()
	a.NoError(err)
	a.Equal("one", string(got1))

	msg2 := &pb.Frame{Kind: &pb.Frame_Msg{Msg: &pb.Message{Data: []byte("two")}}}
	b2, _ := proto.Marshal(msg2)
	a.NoError(serverCh.WriteBytes(b2))

	got2, err := conn.ReadBytes()
	a.NoError(err)
	a.Equal("two", string(got2))
}

func TestListenerStop_PreventsNewConnections(t *testing.T) {
	a := require.New(t)
	listener, serverCh := setupListener(t)

	msg1 := &pb.Frame{Kind: &pb.Frame_Msg{Msg: &pb.Message{Data: []byte("first")}}}
	b1, _ := proto.Marshal(msg1)
	a.NoError(serverCh.WriteBytes(b1))

	conn, err := listener.Accept()
	a.NoError(err)
	defer conn.Close()

	_, err = conn.ReadBytes()
	a.NoError(err)

	listener.Stop()

	msg2 := &pb.Frame{Kind: &pb.Frame_Msg{Msg: &pb.Message{Data: []byte("still here")}}}
	b2, _ := proto.Marshal(msg2)
	a.NoError(serverCh.WriteBytes(b2))

	got, err := conn.ReadBytes()
	a.NoError(err)
	a.Equal("still here", string(got))

	_, err = listener.Accept()
	a.ErrorIs(err, net.ErrClosed)
}

func TestListenerClose_CleansUpActiveConn(t *testing.T) {
	a := require.New(t)
	listener, serverCh := setupListener(t)

	msg := &pb.Frame{Kind: &pb.Frame_Msg{Msg: &pb.Message{Data: []byte("data")}}}
	b, _ := proto.Marshal(msg)
	a.NoError(serverCh.WriteBytes(b))

	conn, err := listener.Accept()
	a.NoError(err)

	_, err = conn.ReadBytes()
	a.NoError(err)

	a.NoError(listener.Close())

	_, err = conn.ReadBytes()
	a.Error(err)
}

func TestRelayConnReadPump_PingReply(t *testing.T) {
	a := require.New(t)
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	serverReady := make(chan struct{}, 1)
	var serverCh *exchange.Channel
	go func() {
		ch, err := exchange.Accept(newTCPAdapter(s))
		if err != nil {
			serverReady <- struct{}{}
			return
		}
		serverCh = ch
		serverReady <- struct{}{}
	}()

	clientCh, err := exchange.Initiate(newTCPAdapter(c))
	a.NoError(err)
	defer clientCh.Close()
	<-serverReady
	defer serverCh.Close()

	var mu sync.Mutex
	rc := newRelayConn(t.Context(), clientCh, &mu)
	rc.closeFn = func() { clientCh.Close() }
	defer rc.Close()

	go rc.readPump()

	ping := &pb.Frame{Kind: &pb.Frame_Ping{Ping: &pb.Ping{}}}
	b, _ := proto.Marshal(ping)
	a.NoError(serverCh.WriteBytes(b))

	data, err := serverCh.ReadBytes()
	a.NoError(err)
	var frame pb.Frame
	a.NoError(proto.Unmarshal(data, &frame))
	a.IsType(&pb.Frame_Pong{}, frame.Kind)
}

func TestRelayConnContextCancel_CleansUp(t *testing.T) {
	a := require.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	rc := newRelayConn(ctx, nil, nil)

	done := make(chan error, 1)
	go func() {
		_, err := rc.ReadBytes()
		done <- err
	}()

	select {
	case <-done:
		a.Fail("ReadBytes returned before context was cancelled")
	case <-time.After(100 * time.Millisecond):
	}

	cancel()

	select {
	case err := <-done:
		a.ErrorIs(err, io.EOF)
	case <-time.After(2 * time.Second):
		a.Fail("ReadBytes did not return after context cancellation")
	}
}

func TestListenHandshake_WithToken(t *testing.T) {
	a := require.New(t)
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	regToken := make(chan []byte, 1)
	go func() {
		rw := newTCPAdapter(s)
		ch, err := exchange.Accept(rw)
		if err != nil {
			regToken <- nil
			return
		}
		defer ch.Close()

		data, err := ch.ReadBytes()
		if err != nil {
			regToken <- nil
			return
		}
		var f pb.Frame
		if err := proto.Unmarshal(data, &f); err != nil {
			regToken <- nil
			return
		}
		reg := f.GetRegister()
		if reg == nil {
			regToken <- nil
			return
		}
		regToken <- reg.GetToken()

		registered := &pb.Frame{
			Kind: &pb.Frame_Registered{
				Registered: &pb.Registered{
					Token:      []byte("from-relay"),
					TtlSeconds: 300,
				},
			},
		}
		b, _ := proto.Marshal(registered)
		ch.WriteBytes(b)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	staticToken := []byte("static-token-1234")
	result, err := listenHandshake(ctx, newTCPAdapter(c), func() {
		c.Close()
	}, WithToken(staticToken))
	a.NoError(err)
	defer result.Listener.Close()

	got := <-regToken
	a.Equal(staticToken, got)
}

func TestDialHandshake_WithAuth(t *testing.T) {
	a := require.New(t)
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	go func() {
		rw := newTCPAdapter(s)
		ch, err := exchange.Accept(rw)
		if err != nil {
			return
		}
		defer ch.Close()

		data, err := ch.ReadBytes()
		if err != nil {
			return
		}
		var f pb.Frame
		if err := proto.Unmarshal(data, &f); err != nil {
			return
		}
		if f.GetAuth() == nil {
			return
		}

		authResp := &pb.Frame{
			Kind: &pb.Frame_Auth{Auth: &pb.Auth{Psk: []byte("sekret")}},
		}
		b, _ := proto.Marshal(authResp)
		ch.WriteBytes(b)

		data, err = ch.ReadBytes()
		if err != nil {
			return
		}
		var f2 pb.Frame
		if err := proto.Unmarshal(data, &f2); err != nil {
			return
		}
		if f2.GetRegister() == nil {
			return
		}

		registered := &pb.Frame{
			Kind: &pb.Frame_Registered{
				Registered: &pb.Registered{Token: []byte("auth-token")},
			},
		}
		b, _ = proto.Marshal(registered)
		ch.WriteBytes(b)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rc, err := relayHandshake(ctx, newTCPAdapter(c), []byte("my-token"), func() {
		c.Close()
	}, WithPassword("sekret"))
	a.NoError(err)
	defer rc.Close()
}

func TestListenerMultipleBufferedMessages(t *testing.T) {
	a := require.New(t)
	listener, serverCh := setupListener(t)

	for _, data := range []string{"first", "second", "third"} {
		msg := &pb.Frame{Kind: &pb.Frame_Msg{Msg: &pb.Message{Data: []byte(data)}}}
		b, _ := proto.Marshal(msg)
		a.NoError(serverCh.WriteBytes(b))
	}

	conn, err := listener.Accept()
	a.NoError(err)
	defer conn.Close()

	for _, want := range []string{"first", "second", "third"} {
		got, err := conn.ReadBytes()
		a.NoError(err)
		a.Equal(want, string(got))
	}
}
