package main

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// server_started, get_server_status and get_share_info report the
// address that the server is bound to, not the one asked for, whose port
// may be 0.
func TestServerReportsBoundAddr(t *testing.T) {
	tests := []struct {
		transport string
		scheme    string
	}{
		{transport: "", scheme: "tcp"},
		{transport: "tcp", scheme: "tcp"},
		{transport: "udp", scheme: "udp"},
		{transport: "direct-p2p", scheme: "direct-p2p"},
	}
	for _, tt := range tests {
		t.Run(tt.scheme+"/"+tt.transport, func(t *testing.T) {
			a := require.New(t)
			d, rec := newTestDaemon(t, VerificationModeQuick, false)
			t.Cleanup(d.stopServer)

			d.handleStartServer(Command{
				ID: "start",
				Params: mustJSON(StartServerParams{
					Addr: "127.0.0.1:0", Transport: tt.transport,
					DirectPeerAddr: "127.0.0.1:9",
				}),
			})
			evt := rec.waitFor(t, func(e recordedEvent) bool {
				return e.ID == "start"
			})
			a.Equal(EvtServerStarted, evt.Evt, "start failed: %v", evt.Data)
			addr, _ := evt.Data["addr"].(string)
			host, port, err := net.SplitHostPort(addr)
			a.NoError(err)
			a.Equal("127.0.0.1", host)
			a.NotEqual("0", port)
			if tt.scheme == "tcp" {
				conn, err := net.Dial("tcp", addr)
				a.NoError(err, "nothing listens on %s", addr)
				a.NoError(conn.Close())
			} else {
				udpAddr, err := net.ResolveUDPAddr("udp4", addr)
				a.NoError(err)
				_, err = net.ListenUDP("udp4", udpAddr)
				a.Error(err, "nothing is bound to %s", addr)
			}

			d.handleGetServerStatus(Command{ID: "status"})
			evt = rec.waitFor(t, func(e recordedEvent) bool {
				return e.ID == "status"
			})
			a.Equal(addr, evt.Data["addr"])

			d.handleGetShareInfo(Command{ID: "share"})
			evt = rec.waitFor(t, func(e recordedEvent) bool {
				return e.ID == "share"
			})
			a.Equal(EvtResponse, evt.Evt, "share failed: %v", evt.Data)
			a.Equal(tt.scheme+"://"+addr, evt.Data["url"])
			a.Equal("127.0.0.1", evt.Data["address"])
			a.Equal(port, evt.Data["port"])
		})
	}
}

func TestParseServerAddr(t *testing.T) {
	tests := []struct {
		addr       string
		host       string
		port       string
		autoDetect bool
	}{
		{addr: "127.0.0.1:9000", host: "127.0.0.1", port: "9000"},
		{addr: ":9000", port: "9000", autoDetect: true},
		{addr: "0.0.0.0:9000", port: "9000", autoDetect: true},
		{addr: "[::]:9000", port: "9000", autoDetect: true},
		{addr: "[::1]:9000", host: "::1", port: "9000"},
		{addr: "example.com:9000", host: "example.com", port: "9000"},
		{addr: "bad"},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			a := require.New(t)
			host, port, autoDetect := parseServerAddr(tt.addr)
			a.Equal(tt.host, host)
			a.Equal(tt.port, port)
			a.Equal(tt.autoDetect, autoDetect)
		})
	}
}
