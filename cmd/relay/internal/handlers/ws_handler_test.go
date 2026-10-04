package handlers

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/cmd/relay/internal/config"
	"github.com/kamune-org/kamune/cmd/relay/internal/services"
	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/relayconn/pb"
)

// testConfig returns a config that passes Validate, with the rate limiter
// on at the given quota (0 turns it off).
func testConfig(quota uint64) config.Config {
	return config.Config{
		WS: config.WS{Enabled: true, Address: "127.0.0.1:0"},
		Session: config.Session{
			TokenTTL:              time.Minute,
			MaxConcurrentSessions: 100,
		},
		RateLimit: config.RateLimit{
			Disabled:   quota == 0,
			TimeWindow: time.Minute,
			Quota:      quota,
			MaxEntries: 100,
		},
	}
}

// newTestHandler builds a Handler over a real Service for cfg.
func newTestHandler(t *testing.T, cfg config.Config) *Handler {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srvc, err := services.New(ctx, cfg)
	require.New(t).NoError(err)
	return New(srvc, cfg)
}

func TestHandler_ClientIPHeaderFromConfig(t *testing.T) {
	tests := []struct {
		name   string
		header string
		lines  []headerLine
		want   string
	}{
		{
			name:  "unset reads x-forwarded-for",
			lines: []headerLine{{"X-Real-Ip", "203.0.113.99"}, {"X-Forwarded-For", "198.51.100.7"}},
			want:  "198.51.100.7",
		},
		{
			name:   "lower case name is canonicalized",
			header: "cf-connecting-ip",
			lines:  []headerLine{{"X-Forwarded-For", "203.0.113.99"}, {"CF-Connecting-IP", "198.51.100.7"}},
			want:   "198.51.100.7",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			cfg := testConfig(0)
			cfg.Server.TrustedProxies = []string{"127.0.0.0/8"}
			cfg.Server.ClientIPHeader = tc.header
			h := newTestHandler(t, cfg)
			r := newRequest("127.0.0.1:1234", tc.lines...)
			a.Equal(tc.want, h.clientIP(r))
		})
	}
}

func TestWebSocketHandler_RateLimitsIPv6ByPrefix(t *testing.T) {
	cfg := testConfig(1)
	cfg.Server.TrustedProxies = []string{"127.0.0.0/8"}
	h := newTestHandler(t, cfg)

	tests := []struct {
		client  string
		limited bool
	}{
		{client: "2001:db8:1:2::1", limited: false},
		{client: "2001:db8:1:2:ffff:ffff:ffff:2", limited: true},
		{client: "2001:db8:1:3::1", limited: false},
	}
	for _, tc := range tests {
		a := require.New(t)
		r := newRequest(
			"127.0.0.1:1234", headerLine{"X-Forwarded-For", tc.client},
		)
		w := httptest.NewRecorder()
		h.WebSocketHandler(w, r)
		if tc.limited {
			a.Equal(http.StatusTooManyRequests, w.Code, tc.client)
		} else {
			a.NotEqual(http.StatusTooManyRequests, w.Code, tc.client)
		}
	}
}

// dialWS opens a WebSocket to the /ws route of srv.
func dialWS(t *testing.T, srv *httptest.Server) *wsAdapter {
	t.Helper()
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, url, nil)
	require.New(t).NoError(err)
	t.Cleanup(func() { _ = conn.CloseNow() })
	return &wsAdapter{conn: conn}
}

func TestWebSocketHandler_UpgradeOutlivesRequestTimeouts(t *testing.T) {
	a := require.New(t)
	h := newTestHandler(t, testConfig(0))
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", h.WebSocketHandler)
	srv := httptest.NewUnstartedServer(mux)
	// The request timeouts must not carry over to the hijacked socket.
	const timeout = 300 * time.Millisecond
	srv.Config.ReadTimeout = timeout
	srv.Config.WriteTimeout = timeout
	srv.Start()
	t.Cleanup(srv.Close)

	listener, reg := dialClientRW(
		t, dialWS(t, srv), "", "", pb.Register_MODE_CREATE, nil,
	)
	dialer, _ := dialClientRW(
		t, dialWS(t, srv), "", "", pb.Register_MODE_JOIN, reg.GetToken(),
	)

	time.Sleep(3 * timeout)

	for _, dir := range []struct {
		from, to *exchange.Channel
		data     string
	}{
		{from: listener, to: dialer, data: "listener to dialer"},
		{from: dialer, to: listener, data: "dialer to listener"},
	} {
		sendFrame(t, dir.from, &pb.Frame{
			Kind: &pb.Frame_Msg{Msg: &pb.Message{Data: []byte(dir.data)}},
		})
		got := readFrame(t, dir.to)
		a.NotNil(got.GetMsg(), "expected Msg frame, got %T", got.Kind)
		a.Equal(dir.data, string(got.GetMsg().GetData()))
	}
}

func TestHandler_Listener(t *testing.T) {
	tests := []struct {
		name     string
		quota    uint64
		trusted  []string
		accepted []bool
	}{
		{
			name:     "direct peer over quota is closed",
			quota:    1,
			accepted: []bool{true, false, false},
		},
		{
			name:     "trusted proxy is not charged",
			quota:    1,
			trusted:  []string{"127.0.0.0/8"},
			accepted: []bool{true, true, true},
		},
		{
			name:     "rate limit off",
			accepted: []bool{true, true, true},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			cfg := testConfig(tc.quota)
			cfg.Server.TrustedProxies = tc.trusted
			h := newTestHandler(t, cfg)

			ln, err := net.Listen("tcp", "127.0.0.1:0")
			a.NoError(err)
			wrapped := h.Listener(ln)
			t.Cleanup(func() { _ = wrapped.Close() })
			accepted := make(chan net.Conn, len(tc.accepted))
			go func() {
				for {
					c, err := wrapped.Accept()
					if err != nil {
						return
					}
					t.Cleanup(func() { _ = c.Close() })
					accepted <- c
				}
			}()

			for i, want := range tc.accepted {
				c, err := net.Dial("tcp", ln.Addr().String())
				a.NoError(err)
				t.Cleanup(func() { _ = c.Close() })
				if want {
					select {
					case <-accepted:
					case <-time.After(10 * time.Second):
						t.Fatalf("connection %d was not accepted", i)
					}
					continue
				}
				a.NoError(c.SetReadDeadline(time.Now().Add(10 * time.Second)))
				_, err = c.Read(make([]byte, 1))
				a.Error(err)
				var ne net.Error
				a.False(
					errors.As(err, &ne) && ne.Timeout(),
					"connection %d over quota must be closed", i,
				)
			}
		})
	}
}
