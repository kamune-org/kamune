package relayconn

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/relayconn/pb"
)

// echoRelay plays the relay for one client on rw: it completes the
// handshake, sends greeting as a Msg frame and then sends every Msg
// frame it receives back to the client.
func echoRelay(rw exchange.ReadWriter, greeting []byte) {
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
	token := f.GetRegister().GetToken()
	if len(token) == 0 {
		token = bytes.Repeat([]byte{0x5a}, relayTokenSize)
	}
	b, _ := proto.Marshal(registeredFrame(token))
	if err := ch.WriteBytes(b); err != nil {
		return
	}
	if err := ch.WriteBytes(msgFrame(greeting)); err != nil {
		return
	}
	for {
		data, err := ch.ReadBytes()
		if err != nil {
			return
		}
		if err := proto.Unmarshal(data, &f); err != nil {
			return
		}
		if f.GetMsg() == nil {
			continue
		}
		if err := ch.WriteBytes(data); err != nil {
			return
		}
	}
}

// echoRelayTCP serves echoRelay over TCP and returns its address.
func echoRelayTCP(t *testing.T, greeting []byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.New(t).NoError(err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				echoRelay(newTCPAdapter(c), greeting)
			}()
		}
	}()
	return ln.Addr().String()
}

// echoRelayWS serves echoRelay over WebSocket and returns its address.
func echoRelayWS(t *testing.T, greeting []byte) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			conn, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer conn.CloseNow()
			echoRelay(&wsAdapter{conn: conn, ctx: r.Context()}, greeting)
		},
	))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

// TestSessionOutlivesHandshakeContext cancels the context given to a
// Dial or Listen helper once it has returned, as a caller using a
// timeout context with a deferred cancel does, and checks that the
// listener still accepts and the connection still carries data both
// ways.
func TestSessionOutlivesHandshakeContext(t *testing.T) {
	token := bytes.Repeat([]byte{0x21, 0x43}, peerTokenSize/2)
	dial := func(
		fn func(context.Context, string, []byte, ...Option) (*RelayConn, error),
	) func(context.Context, string) (func() (kamune.Conn, error), error) {
		return func(
			ctx context.Context, addr string,
		) (func() (kamune.Conn, error), error) {
			rc, err := fn(ctx, addr, token)
			return func() (kamune.Conn, error) { return rc, nil }, err
		}
	}
	listen := func(
		fn func(context.Context, string, ...Option) (*ListenResult, error),
	) func(context.Context, string) (func() (kamune.Conn, error), error) {
		return func(
			ctx context.Context, addr string,
		) (func() (kamune.Conn, error), error) {
			res, err := fn(ctx, addr)
			if err != nil {
				return nil, err
			}
			t.Cleanup(func() { _ = res.Listener.Close() })
			return res.Listener.Accept, nil
		}
	}

	tests := []struct {
		open  func(context.Context, string) (func() (kamune.Conn, error), error)
		relay func(*testing.T, []byte) string
		name  string
	}{
		{name: "dial ws", relay: echoRelayWS, open: dial(DialRelay)},
		{name: "dial tcp", relay: echoRelayTCP, open: dial(DialRelayTCP)},
		{name: "listen ws", relay: echoRelayWS, open: listen(ListenRelay)},
		{
			name:  "listen tcp",
			relay: echoRelayTCP, open: listen(ListenRelayTCP),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			addr := tc.relay(t, []byte("hello"))

			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			accept, err := tc.open(ctx, addr)
			cancel()
			a.NoError(err)

			conn, err := accept()
			a.NoError(err)
			defer conn.Close()
			a.NoError(conn.SetDeadline(time.Now().Add(5 * time.Second)))

			got, err := conn.ReadBytes()
			a.NoError(err)
			a.Equal("hello", string(got))
			a.NoError(conn.WriteBytes([]byte("ping")))
			got, err = conn.ReadBytes()
			a.NoError(err)
			a.Equal("ping", string(got))
		})
	}
}

// TestHandshakeStalledWebSocket checks that a WebSocket handshake ends
// promptly when a relay accepts the upgrade and then never answers,
// whether the context or the handshake timeout ends it. Closing the
// WebSocket alone would wait out its close handshake first.
func TestHandshakeStalledWebSocket(t *testing.T) {
	token := bytes.Repeat([]byte{0x21}, peerTokenSize)
	short := WithHandshakeTimeout(300 * time.Millisecond)
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			conn, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer conn.CloseNow()
			<-r.Context().Done()
		},
	))
	t.Cleanup(srv.Close)
	addr := strings.TrimPrefix(srv.URL, "http://")

	tests := []struct {
		run    func(ctx context.Context) error
		name   string
		ctxEnd bool
	}{
		{
			name: "dial ctx", ctxEnd: true,
			run: func(ctx context.Context) error {
				_, err := DialRelay(ctx, addr, token)
				return err
			},
		},
		{
			name: "listen ctx", ctxEnd: true,
			run: func(ctx context.Context) error {
				_, err := ListenRelay(ctx, addr)
				return err
			},
		},
		{
			name: "dial timeout",
			run: func(ctx context.Context) error {
				_, err := DialRelay(ctx, addr, token, short)
				return err
			},
		},
		{
			name: "listen timeout",
			run: func(ctx context.Context) error {
				_, err := ListenRelay(ctx, addr, short)
				return err
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			ctx := t.Context()
			if tc.ctxEnd {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 300*time.Millisecond)
				defer cancel()
			}
			errCh := make(chan error, 1)
			go func() { errCh <- tc.run(ctx) }()
			select {
			case err := <-errCh:
				a.ErrorIs(err, context.DeadlineExceeded)
			case <-time.After(3 * time.Second):
				a.Fail("handshake with a stalled relay did not return")
			}
		})
	}
}
