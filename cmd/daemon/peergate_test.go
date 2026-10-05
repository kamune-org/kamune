package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/pkg/fingerprint"
)

func TestPeerGates(t *testing.T) {
	bob, carol, mallory := []byte("bob"), []byte("carol"), []byte("mallory")
	tests := []struct {
		name  string
		gate  peerGate
		admit [][]byte
		deny  [][]byte
	}{
		{
			name:  "random relay token",
			gate:  &tokenTracker{},
			admit: [][]byte{bob, mallory},
		},
		{
			name:  "static relay token",
			gate:  &tokenTracker{peer: bob},
			admit: [][]byte{bob},
			deny:  [][]byte{mallory},
		},
		{
			name: "p2p listener with static tokens",
			gate: &p2pListener{tokens: []listenerToken{
				{peer: bob}, {peer: carol},
			}},
			admit: [][]byte{bob, carol},
			deny:  [][]byte{mallory},
		},
		{
			name: "p2p listener with a random token",
			gate: &p2pListener{tokens: []listenerToken{
				{peer: bob}, {},
			}},
			admit: [][]byte{bob, mallory},
		},
		{
			name: "p2p listener without tokens",
			gate: &p2pListener{},
			deny: [][]byte{bob},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			for _, k := range tt.admit {
				a.True(admittedBy(tt.gate, k), "%s denied", k)
			}
			for _, k := range tt.deny {
				a.False(admittedBy(tt.gate, k), "%s admitted", k)
			}
		})
	}
	require.New(t).True(admittedBy(nil, bob))
}

// The BUS-01 scenario on a relay server: a token generated for Bob is a
// hash of both keys, so Mallory, a stored peer whom Quick mode admits,
// can join it too. The server drops her session before it is shown.
func TestStaticRelayTokenAdmitsOnlyItsPeer(t *testing.T) {
	tests := []struct {
		name    string
		toBob   bool
		wantRun bool
	}{
		{name: "another stored peer is dropped"},
		{name: "the token's peer is admitted", toBob: true, wantRun: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			relay := newFakeRelay(t)
			server, serverRec := newTestDaemon(t, VerificationModeQuick, false)
			mallory, malloryRec := newTestDaemon(
				t, VerificationModeQuick, false,
			)
			malloryKey := storeAs(t, server, mallory, "Mallory")
			storeAs(t, mallory, server, "Server")
			bobKey := newTestPeerKey(t)
			if tt.toBob {
				bobKey = malloryKey
			}

			startRelayServer(t, server, serverRec, relay)
			server.handleGenerateRelayToken(Command{
				ID: "token",
				Params: mustJSON(GenerateRelayTokenParams{
					PeerPubB64: fingerprint.Base64(bobKey),
				}),
			})
			evt := serverRec.waitFor(t, func(e recordedEvent) bool {
				return e.ID == "token"
			})
			a.Equal(EvtResponse, evt.Evt, "generate failed: %v", evt.Data)
			a.Equal("static", evt.Data["mode"])
			token, _ := evt.Data["token"].(string)

			id := dialRelay(t, mallory, malloryRec, relay, token)
			if tt.wantRun {
				evt := serverRec.waitFor(t, isEvent(EvtSessionStarted))
				a.Equal(id, evt.Data["session_id"])
				a.Equal("Mallory", evt.Data["peer_name"])
				return
			}
			serverRec.waitFor(t, func(e recordedEvent) bool {
				msg, _ := e.Data["message"].(string)
				return e.Evt == EvtLogEntry && strings.Contains(msg,
					"the token it used was made for another peer")
			})
			malloryRec.waitFor(t, func(e recordedEvent) bool {
				return e.Evt == EvtSessionClosed &&
					e.Data["session_id"] == id
			})
			serverRec.mu.Lock()
			defer serverRec.mu.Unlock()
			for _, e := range serverRec.events {
				a.NotEqual(EvtSessionStarted, e.Evt, "%v", e.Data)
			}
		})
	}
}
