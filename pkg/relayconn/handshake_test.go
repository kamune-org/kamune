package relayconn

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/relayconn/pb"
)

func TestCheckRegisteredToken(t *testing.T) {
	sent := bytes.Repeat([]byte{0x01}, peerTokenSize)
	other := bytes.Repeat([]byte{0x02}, peerTokenSize)

	tests := []struct {
		wantErr error
		name    string
		got     []byte
		sent    []byte
	}{
		{nil, "echoed token", sent, sent},
		{ErrRelayTokenMismatch, "different token", other, sent},
		{ErrRelayTokenMismatch, "truncated echo", sent[:16], sent},
		{ErrRelayTokenMismatch, "missing echo", nil, sent},
		{nil, "assigned 16 bytes", other[:relayTokenSize], nil},
		{nil, "assigned 32 bytes", other, nil},
		{ErrInvalidRelayToken, "assigned empty", nil, nil},
		{ErrInvalidRelayToken, "assigned 10 bytes", other[:10], nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			err := checkRegisteredToken(tc.got, tc.sent)
			if tc.wantErr == nil {
				a.NoError(err)
				return
			}
			a.ErrorIs(err, tc.wantErr)
		})
	}
}

// relayReplying runs a relay stand-in on conn that answers the client's
// Register with the frame reply builds from it.
func relayReplying(conn net.Conn, reply func(*pb.Register) *pb.Frame) {
	ch, err := exchange.Accept(newTCPAdapter(conn))
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
	b, _ := proto.Marshal(reply(f.GetRegister()))
	_ = ch.WriteBytes(b)
	_, _ = ch.ReadBytes()
}

func registeredFrame(token []byte) *pb.Frame {
	return &pb.Frame{Kind: &pb.Frame_Registered{
		Registered: &pb.Registered{Token: token, TtlSeconds: 60},
	}}
}

// TestHandshakeRegisteredToken checks that both handshakes reject a
// Registered frame whose token does not match what was registered.
func TestHandshakeRegisteredToken(t *testing.T) {
	token := bytes.Repeat([]byte{0x33}, peerTokenSize)
	other := bytes.Repeat([]byte{0x44}, peerTokenSize)
	echo := func(r *pb.Register) *pb.Frame {
		return registeredFrame(r.GetToken())
	}
	replace := func(r *pb.Register) *pb.Frame {
		return registeredFrame(other)
	}
	short := func(r *pb.Register) *pb.Frame {
		return registeredFrame([]byte("ten-bytes!"))
	}
	ping := func(r *pb.Register) *pb.Frame {
		return &pb.Frame{Kind: &pb.Frame_Ping{Ping: &pb.Ping{}}}
	}

	listen := func(
		ctx context.Context, c net.Conn, opts ...Option,
	) error {
		res, err := listenHandshake(
			ctx, newTCPAdapter(c), func() { c.Close() }, opts...,
		)
		if err == nil {
			res.Listener.Close()
		}
		return err
	}
	dial := func(ctx context.Context, c net.Conn, _ ...Option) error {
		rc, err := relayHandshake(
			ctx, newTCPAdapter(c), token, func() { c.Close() },
		)
		if err == nil {
			rc.Close()
		}
		return err
	}

	tests := []struct {
		reply   func(*pb.Register) *pb.Frame
		run     func(context.Context, net.Conn, ...Option) error
		wantErr error
		name    string
		opts    []Option
		errText string
	}{
		{
			name:  "listen static echoed",
			reply: echo, run: listen, opts: []Option{WithToken(token)},
		},
		{
			name:  "listen static replaced",
			reply: replace, run: listen, opts: []Option{WithToken(token)},
			wantErr: ErrRelayTokenMismatch,
		},
		{
			name:  "listen assigned short",
			reply: short, run: listen,
			wantErr: ErrInvalidRelayToken,
		},
		{
			name:  "listen wrong frame",
			reply: ping, run: listen,
			errText: "expected registered",
		},
		{name: "dial echoed", reply: echo, run: dial},
		{
			name:  "dial replaced",
			reply: replace, run: dial,
			wantErr: ErrRelayTokenMismatch,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			c, s := net.Pipe()
			defer c.Close()
			defer s.Close()
			go relayReplying(s, tc.reply)

			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			err := tc.run(ctx, c, tc.opts...)
			switch {
			case tc.wantErr != nil:
				a.ErrorIs(err, tc.wantErr)
			case tc.errText != "":
				a.ErrorContains(err, tc.errText)
			default:
				a.NoError(err)
			}
		})
	}
}

// tarpit returns the address of a TCP server that accepts connections
// and never writes to them.
func tarpit(t *testing.T) string {
	t.Helper()
	a := require.New(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	a.NoError(err)
	var (
		mu    sync.Mutex
		conns []net.Conn
	)
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	return ln.Addr().String()
}

// TestHandshakeStalledRelay checks that every helper gives up on a
// relay that accepts the connection and then never answers, both when
// the caller's context ends and when only the handshake timeout bounds
// the handshake.
func TestHandshakeStalledRelay(t *testing.T) {
	token := bytes.Repeat([]byte{0x21}, peerTokenSize)
	insecure := &tls.Config{InsecureSkipVerify: true}
	short := WithHandshakeTimeout(300 * time.Millisecond)

	tests := []struct {
		run    func(ctx context.Context, addr string) error
		name   string
		ctxEnd bool
	}{
		{
			name: "listen tcp ctx", ctxEnd: true,
			run: func(ctx context.Context, addr string) error {
				_, err := ListenRelayTCP(ctx, addr)
				return err
			},
		},
		{
			name: "listen tls ctx", ctxEnd: true,
			run: func(ctx context.Context, addr string) error {
				_, err := ListenRelayTLS(ctx, addr, insecure)
				return err
			},
		},
		{
			name: "dial tls ctx", ctxEnd: true,
			run: func(ctx context.Context, addr string) error {
				_, err := DialRelayTLS(ctx, addr, token, insecure)
				return err
			},
		},
		{
			name: "listen tcp timeout",
			run: func(ctx context.Context, addr string) error {
				_, err := ListenRelayTCP(ctx, addr, short)
				return err
			},
		},
		{
			name: "dial tcp timeout",
			run: func(ctx context.Context, addr string) error {
				_, err := DialRelayTCP(ctx, addr, token, short)
				return err
			},
		},
		{
			name: "listen tls timeout",
			run: func(ctx context.Context, addr string) error {
				_, err := ListenRelayTLS(ctx, addr, insecure, short)
				return err
			},
		},
		{
			name: "listen ws timeout",
			run: func(ctx context.Context, addr string) error {
				_, err := ListenRelay(ctx, addr, short)
				return err
			},
		},
		{
			name: "dial ws timeout",
			run: func(ctx context.Context, addr string) error {
				_, err := DialRelay(ctx, addr, token, short)
				return err
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			addr := tarpit(t)
			ctx := context.Background()
			if tc.ctxEnd {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(
					ctx, 300*time.Millisecond,
				)
				defer cancel()
			}

			errCh := make(chan error, 1)
			go func() { errCh <- tc.run(ctx, addr) }()
			select {
			case err := <-errCh:
				a.ErrorIs(err, context.DeadlineExceeded)
			case <-time.After(3 * time.Second):
				a.Fail("handshake with a stalled relay did not return")
			}
		})
	}
}
