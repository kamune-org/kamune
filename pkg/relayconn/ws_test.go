package relayconn

import (
	"bytes"
	"context"
	"crypto/tls"
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

// wsRelayServer starts a WebSocket relay stand-in that completes the
// relay handshake, echoes the registered token (or assigns a 16-byte
// one) and then sends payload as a single Msg frame.
func wsRelayServer(
	t *testing.T, useTLS bool, payload []byte,
) (addr string, tlsCfg *tls.Config) {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		conn.SetReadLimit(1 << 20)
		ch, err := exchange.Accept(&wsAdapter{conn: conn, ctx: r.Context()})
		if err != nil {
			return
		}
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
			token = bytes.Repeat([]byte{0x5a}, 16)
		}
		reg := &pb.Frame{Kind: &pb.Frame_Registered{
			Registered: &pb.Registered{Token: token, TtlSeconds: 60},
		}}
		b, _ := proto.Marshal(reg)
		if err := ch.WriteBytes(b); err != nil {
			return
		}
		msg := &pb.Frame{Kind: &pb.Frame_Msg{
			Msg: &pb.Message{Data: payload},
		}}
		b, _ = proto.Marshal(msg)
		if err := ch.WriteBytes(b); err != nil {
			return
		}
		for {
			if _, err := ch.ReadBytes(); err != nil {
				return
			}
		}
	})

	var server *httptest.Server
	if useTLS {
		server = httptest.NewTLSServer(handler)
		tr := server.Client().Transport.(*http.Transport)
		tlsCfg = tr.TLSClientConfig
	} else {
		server = httptest.NewServer(handler)
	}
	t.Cleanup(server.Close)
	addr = server.URL[strings.Index(server.URL, "://")+3:]
	return addr, tlsCfg
}

// TestWebSocketLargeFrame checks that every client WebSocket entry
// point accepts a relay frame above coder/websocket's 32 KiB default
// read limit.
func TestWebSocketLargeFrame(t *testing.T) {
	payload := bytes.Repeat([]byte{0xab}, 65000)
	token := bytes.Repeat([]byte{0x11}, peerTokenSize)

	dial := func(
		ctx context.Context, addr string, cfg *tls.Config, wss bool,
	) (kamune.Conn, error) {
		if wss {
			return DialRelayWSS(ctx, addr, token, cfg)
		}
		return DialRelay(ctx, addr, token)
	}
	listen := func(
		ctx context.Context, addr string, cfg *tls.Config, wss bool,
	) (kamune.Conn, error) {
		var (
			res *ListenResult
			err error
		)
		if wss {
			res, err = ListenRelayWSS(ctx, addr, cfg)
		} else {
			res, err = ListenRelay(ctx, addr)
		}
		if err != nil {
			return nil, err
		}
		t.Cleanup(func() { res.Listener.Close() })
		return res.Listener.Accept()
	}

	tests := []struct {
		connect func(
			context.Context, string, *tls.Config, bool,
		) (kamune.Conn, error)
		name string
		wss  bool
	}{
		{name: "dial ws", connect: dial},
		{name: "dial wss", wss: true, connect: dial},
		{name: "listen ws", connect: listen},
		{name: "listen wss", wss: true, connect: listen},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			addr, cfg := wsRelayServer(t, tc.wss, payload)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()

			conn, err := tc.connect(ctx, addr, cfg, tc.wss)
			a.NoError(err)
			defer conn.Close()
			a.NoError(conn.SetDeadline(time.Now().Add(5 * time.Second)))

			got, err := conn.ReadBytes()
			a.NoError(err)
			a.Equal(payload, got)
		})
	}
}
