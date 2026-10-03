package relayconn

import (
	"bytes"
	"context"
	"net"
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
