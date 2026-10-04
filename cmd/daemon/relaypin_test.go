package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/pkg/relayconn"
)

func TestParseRelayPin(t *testing.T) {
	fp := strings.Repeat("Ab", 32)
	colons := strings.TrimSuffix(strings.Repeat("ab:", 32), ":")
	want := bytes.Repeat([]byte{0xab}, 32)
	tests := []struct {
		addr string
		pin  string
		want []byte
		ok   bool
	}{
		{addr: "tls://relay.example:8890", ok: true},
		{addr: "tls://relay.example:8890", pin: fp, want: want, ok: true},
		{addr: "wss://relay.example", pin: fp, want: want, ok: true},
		{addr: "relay.example:443", pin: colons, want: want, ok: true},
		{addr: "ws://relay.example", pin: fp},
		{addr: "tcp://relay.example:8889", pin: fp},
		{addr: "tls://relay.example:8890?insecure=true", pin: fp},
		{addr: "tls://relay.example:8890", pin: "ab"},
		{addr: "tls://relay.example:8890", pin: strings.Repeat("x", 64)},
	}
	for _, tt := range tests {
		t.Run(tt.addr+" "+tt.pin, func(t *testing.T) {
			a := require.New(t)
			got, err := parseRelayPin(tt.addr, tt.pin)
			if !tt.ok {
				a.ErrorIs(err, errInvalidRelayPin)
				return
			}
			a.NoError(err)
			a.Equal(tt.want, got)
		})
	}
}

// A relay server and a relay dial reach a relay with a self-signed
// certificate when relay_pin holds its fingerprint, and only then. The
// pin carries over to the relay tokens the server registers later, to
// its share card and to restart_server.
func TestRelayPin(t *testing.T) {
	relay, der := newFakeTLSRelay(t)
	pin := relayconn.CertFingerprint(der)
	server, serverRec := newTestDaemon(t, VerificationModeQuick, false)
	client, clientRec := newTestDaemon(t, VerificationModeQuick, false)
	trustPeer(t, server, client)
	trustPeer(t, client, server)

	n := 0
	start := func(pin string) recordedEvent {
		t.Helper()
		n++
		id := ID(fmt.Sprintf("start-%d", n))
		server.handleStartServer(Command{
			ID: id,
			Params: mustJSON(StartServerParams{
				Transport: "relay", RelayAddr: relay.addr(), RelayPin: pin,
			}),
		})
		return serverRec.waitFor(t, func(e recordedEvent) bool {
			return e.ID == id &&
				(e.Evt == EvtServerStarted || e.Evt == EvtError)
		})
	}
	dial := func(id ID, token, pin string) recordedEvent {
		t.Helper()
		client.handleDial(Command{
			ID: id,
			Params: mustJSON(DialParams{
				Transport: "relay", RelayAddr: relay.addr(),
				Token: token, RelayPin: pin,
			}),
		})
		return clientRec.waitFor(t, func(e recordedEvent) bool {
			return e.ID == id &&
				(e.Evt == EvtSessionStarted || e.Evt == EvtError)
		})
	}

	t.Run("refused", func(t *testing.T) {
		a := require.New(t)
		evt := start("")
		a.Equal("relay_listen_failed", evt.Data["code"])
		a.Contains(evt.Data["error"], "relay_pin")
		evt = start(strings.Repeat("00", 32))
		a.Equal("relay_listen_failed", evt.Data["code"])
		a.Contains(evt.Data["error"], relayconn.ErrCertPinMismatch.Error())

		server.handleStartServer(Command{
			ID: "bad-pin",
			Params: mustJSON(StartServerParams{
				Transport: "relay", RelayAddr: "tcp://relay.example:1",
				RelayPin: pin,
			}),
		})
		evt = serverRec.waitFor(t, func(e recordedEvent) bool {
			return e.ID == "bad-pin"
		})
		a.Equal("invalid_relay_pin", evt.Data["code"])
	})

	a := require.New(t)
	evt := start(pin)
	a.Equal(EvtServerStarted, evt.Evt, "start_server: %v", evt.Data)
	token := generateRelayToken(t, server, serverRec, "token")

	server.handleGetShareInfo(Command{ID: "share"})
	evt = serverRec.waitFor(t, func(e recordedEvent) bool {
		return e.ID == "share"
	})
	a.Equal(EvtResponse, evt.Evt, "get_share_info: %v", evt.Data)
	info, ok := evt.Data["relay_info"].(map[string]any)
	a.True(ok)
	a.Equal(pin, info["pin"])
	a.Contains(evt.Data["url"], "&pin="+pin)

	evt = dial("unpinned", token, "")
	a.Equal(EvtError, evt.Evt, "an unpinned dial reached the relay")
	a.Contains(evt.Data["error"], "relay_pin")
	evt = dial("pinned", token, pin)
	a.Equal(EvtSessionStarted, evt.Evt, "dial: %v", evt.Data)

	server.handleRestartServer(Command{ID: "restart"})
	evt = serverRec.waitFor(t, func(e recordedEvent) bool {
		return e.ID == "restart" &&
			(e.Evt == EvtServerStarted || e.Evt == EvtError)
	})
	a.Equal(EvtServerStarted, evt.Evt, "restart_server: %v", evt.Data)
}
