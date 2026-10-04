package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/pkg/fingerprint"
)

// logMessages returns the messages in d's log buffer.
func logMessages(d *Daemon) []string {
	d.logMu.RLock()
	defer d.logMu.RUnlock()
	msgs := make([]string, len(d.logEntries))
	for i, e := range d.logEntries {
		msgs[i] = e.Message
	}
	return msgs
}

// Log messages name relay and p2p tokens by a short prefix, never in
// full: an unused relay token lets whoever reads the log join the
// session it was made for.
func TestLogsNameTokensByPrefix(t *testing.T) {
	tests := []struct {
		name string
		// run makes tokens on d, logging them, and returns them.
		run func(t *testing.T, d *Daemon, rec *eventRecorder) []string
	}{
		{
			name: "relay",
			run: func(t *testing.T, d *Daemon, rec *eventRecorder) []string {
				a := require.New(t)
				relay := newFakeRelay(t)
				startup := startRelayServer(t, d, rec, relay)
				token := generateRelayToken(t, d, rec, "token")
				d.handleRemoveRelayToken(Command{
					ID: "rm", Params: mustJSON(MapS{"token": token}),
				})
				evt := rec.waitFor(t, func(e recordedEvent) bool {
					return e.ID == "rm"
				})
				a.Equal(EvtResponse, evt.Evt, "remove failed: %v", evt.Data)
				return []string{startup, token}
			},
		},
		{
			name: "p2p",
			run: func(t *testing.T, d *Daemon, rec *eventRecorder) []string {
				a := require.New(t)
				broker := newFakeBroker(t, false)
				d.handleStartServer(Command{
					ID: "start",
					Params: mustJSON(StartServerParams{
						Addr: "127.0.0.1:0", Transport: "p2p",
						BrokerAddr: broker.addr(),
						PeerPubB64: fingerprint.Base64(newTestPeerKey(t)),
					}),
				})
				rec.waitFor(t, isEvent(EvtServerStarted))
				token, err := d.GenerateP2PToken(broker.addr(), "")
				a.NoError(err)
				a.NoError(d.RemoveP2PToken(token))
				return []string{token}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			d, rec := newTestDaemon(t, VerificationModeQuick, false)
			t.Cleanup(d.stopServer)
			tokens := tt.run(t, d, rec)

			msgs := logMessages(d)
			for _, token := range tokens {
				a.Len(token, 32)
				named := false
				for _, msg := range msgs {
					a.NotContains(msg, token)
					named = named || strings.Contains(msg, shortToken(token))
				}
				a.True(named, "no log message names %s", shortToken(token))
			}
		})
	}
}

func TestShortToken(t *testing.T) {
	tests := []struct {
		token string
		want  string
	}{
		{token: "", want: ""},
		{token: "abcd", want: "abcd"},
		{token: "abcdef01", want: "abcdef01"},
		{token: "abcdef0123", want: "abcdef01..."},
		{token: strings.Repeat("ab", 32), want: "abababab..."},
	}
	for _, tt := range tests {
		t.Run(tt.token, func(t *testing.T) {
			a := require.New(t)
			a.Equal(tt.want, shortToken(tt.token))
		})
	}
}
