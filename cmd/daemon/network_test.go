package main

import (
	"fmt"
	"net"
	"testing"
	"time"

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

// start_server and dial refuse a transport they do not know, and a tcp
// or udp one without an address, instead of falling back to a tcp
// listener on every interface.
func TestUnknownTransportIsRefused(t *testing.T) {
	tests := []struct {
		name      string
		transport string
		addr      string
		code      string
	}{
		{name: "capitalised", transport: "Relay", code: "invalid_transport"},
		{name: "upper case", transport: "TCP", addr: "127.0.0.1:0",
			code: "invalid_transport"},
		{name: "unknown", transport: "quic", addr: "127.0.0.1:0",
			code: "invalid_transport"},
		{name: "default without addr", code: "addr_required"},
		{name: "tcp without addr", transport: "tcp", code: "addr_required"},
		{name: "udp without addr", transport: "udp", code: "addr_required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			d, rec := newTestDaemon(t, VerificationModeQuick, false)
			t.Cleanup(d.stopServer)

			d.handleStartServer(Command{
				ID: "start",
				Params: mustJSON(StartServerParams{
					Addr: tt.addr, Transport: tt.transport,
				}),
			})
			evt := rec.waitFor(t, func(e recordedEvent) bool {
				return e.ID == "start"
			})
			a.Equal(EvtError, evt.Evt, "server started: %v", evt.Data)
			a.Equal(tt.code, evt.Data["code"], evt.Data["error"])
			d.mu.RLock()
			running := d.server != nil || d.startCancel != nil
			d.mu.RUnlock()
			a.False(running)

			d.handleDial(Command{
				ID: "dial",
				Params: mustJSON(DialParams{
					Addr: tt.addr, Transport: tt.transport,
				}),
			})
			evt = rec.waitFor(t, func(e recordedEvent) bool {
				return e.ID == "dial"
			})
			a.Equal(EvtError, evt.Evt)
			a.Equal(tt.code, evt.Data["code"], evt.Data["error"])

			d.handleRestartServer(Command{ID: "restart"})
			evt = rec.waitFor(t, func(e recordedEvent) bool {
				return e.ID == "restart"
			})
			a.Equal(EvtError, evt.Evt)
			a.Equal("server_not_started", evt.Data["code"], evt.Data["error"])
		})
	}
}

// get_server_status reports when the running server started, whether or
// not a peer has connected to it, and no start time while none runs.
func TestServerStatusStartedAt(t *testing.T) {
	a := require.New(t)
	d, rec := newTestDaemon(t, VerificationModeQuick, false)
	status := func(id ID) recordedEvent {
		t.Helper()
		d.handleGetServerStatus(Command{ID: id})
		return rec.waitFor(t, func(e recordedEvent) bool { return e.ID == id })
	}

	a.Equal("", status("before").Data["started_at"])
	before := time.Now().Truncate(time.Second)
	startTestServer(t, d, rec)
	after := time.Now()

	evt := status("running")
	a.Equal(true, evt.Data["running"])
	startedAt, err := time.Parse(time.RFC3339, fmt.Sprint(evt.Data["started_at"]))
	a.NoError(err, "started_at %v", evt.Data["started_at"])
	a.False(startedAt.Before(before), "%v", startedAt)
	a.False(startedAt.After(after), "%v", startedAt)

	d.stopServer()
	a.Equal("", status("stopped").Data["started_at"])
}
