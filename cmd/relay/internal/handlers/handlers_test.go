package handlers

import (
	"bufio"
	"log/slog"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/cmd/relay/internal/config"
)

func TestHandler_WarnsOnceWhenTrustedProxyOmitsHeader(t *testing.T) {
	a := require.New(t)
	out := captureLog(t, slog.LevelInfo)
	cfg := testConfig(0)
	cfg.Server.TrustedProxies = []string{"127.0.0.0/8"}
	cfg.Server.ClientIPHeader = "X-Real-IP"
	h := newTestHandler(t, cfg)
	const warning = "without a usable client address header"

	steps := []struct {
		name   string
		remote string
		lines  []headerLine
		warned int
	}{
		{name: "direct peer", remote: "192.0.2.1:1234", warned: 0},
		{
			name:   "proxy sets the header",
			remote: "127.0.0.1:1234",
			lines:  []headerLine{{"X-Real-Ip", "198.51.100.7"}},
			warned: 0,
		},
		{
			name:   "proxy sets another header",
			remote: "127.0.0.1:1234",
			lines:  []headerLine{{"X-Forwarded-For", "198.51.100.7"}},
			warned: 1,
		},
		{name: "no header again", remote: "127.0.0.1:1234", warned: 1},
	}
	for _, st := range steps {
		h.clientIP(newRequest(st.remote, st.lines...))
		a.Equal(
			st.warned, strings.Count(out.String(), warning), st.name,
		)
	}
}

// hijackRecorder is a ResponseWriter whose Hijack hands out conn.
type hijackRecorder struct {
	*httptest.ResponseRecorder
	conn net.Conn
}

func (w hijackRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	brw := bufio.NewReadWriter(
		bufio.NewReader(w.conn), bufio.NewWriter(w.conn),
	)
	return w.conn, brw, nil
}

func TestClearingHijacker_ClearsDeadlines(t *testing.T) {
	a := require.New(t)
	server, client := net.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})
	// The server's request timeouts leave deadlines on the connection,
	// already passed by the time a session is idle.
	a.NoError(server.SetDeadline(time.Now().Add(-time.Second)))

	w := clearingHijacker{hijackRecorder{httptest.NewRecorder(), server}}
	conn, _, err := w.Hijack()
	a.NoError(err)

	go func() { _, _ = client.Write([]byte{1}) }()
	_, err = conn.Read(make([]byte, 1))
	a.NoError(err, "the read deadline must be cleared")

	go func() { _, _ = client.Read(make([]byte, 1)) }()
	_, err = conn.Write([]byte{2})
	a.NoError(err, "the write deadline must be cleared")
}

func TestHandler_ListenerOnlyLimitsWithWSListeners(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*config.Config)
		limited bool
	}{
		{name: "ws on", mutate: func(*config.Config) {}, limited: true},
		{
			name: "wss on",
			mutate: func(c *config.Config) {
				c.WS.Enabled = false
				c.WSS = config.WSS{Enabled: true, Address: "127.0.0.1:0"}
			},
			limited: true,
		},
		{
			name: "no ws listener",
			mutate: func(c *config.Config) {
				c.WS.Enabled = false
				c.TCP = config.TCP{Enabled: true, Address: "127.0.0.1:0"}
			},
		},
		{
			name: "rate limit off",
			mutate: func(c *config.Config) {
				c.RateLimit.Disabled = true
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			cfg := testConfig(1)
			tc.mutate(&cfg)
			h := newTestHandler(t, cfg)
			a.Equal(tc.limited, h.connLimiter != nil)

			ln, err := net.Listen("tcp", "127.0.0.1:0")
			a.NoError(err)
			t.Cleanup(func() { _ = ln.Close() })
			a.Equal(tc.limited, h.Listener(ln) != ln)
		})
	}
}
