package handlers

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
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
