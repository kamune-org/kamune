package main

import (
	"fmt"
	"testing"

	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/stretchr/testify/require"
)

// Every command that takes a peer name refuses one that
// kamune.ValidatePeerName refuses, with invalid_name, before it acts.
func TestCommandsRefuseInvalidNames(t *testing.T) {
	d, rec := newTestDaemon(t, VerificationModeQuick, false)
	key := fingerprint.Base64(newTestPeerKey(t))
	commands := []struct {
		name   string
		handle func(Command)
		params func(name string) any
	}{
		{
			name: "set_my_name", handle: d.handleSetMyName,
			params: func(n string) any { return SetMyNameParams{Name: n} },
		},
		{
			name: "add_peer", handle: d.handleAddPeer,
			params: func(n string) any {
				return AddPeerParams{PublicKey: key, Name: n}
			},
		},
		{
			name: "rename_peer", handle: d.handleRenamePeer,
			params: func(n string) any {
				return RenamePeerParams{PublicKey: key, Name: n}
			},
		},
		{
			name: "rename_session", handle: d.handleRenameSession,
			params: func(n string) any {
				return RenameSessionParams{SessionID: "s", Name: n}
			},
		},
		{
			name: "start_server", handle: d.handleStartServer,
			params: func(n string) any {
				return StartServerParams{Addr: "127.0.0.1:0", Name: n}
			},
		},
		{
			name: "dial", handle: d.handleDial,
			params: func(n string) any {
				return DialParams{Addr: "127.0.0.1:1", Name: n}
			},
		},
	}
	badNames := []string{
		"two\nlines", "Bob\u202e", "\x1b[2Jclear", "zero\u200bwidth",
		"\u2028sep",
	}
	n := 0
	for _, c := range commands {
		for _, name := range badNames {
			t.Run(fmt.Sprintf("%s/%q", c.name, name), func(t *testing.T) {
				a := require.New(t)
				n++
				id := ID(fmt.Sprintf("cmd-%d", n))
				c.handle(Command{ID: id, Params: mustJSON(c.params(name))})
				evt := rec.waitFor(t, func(e recordedEvent) bool {
					return e.ID == id
				})
				a.Equal(EvtError, evt.Evt)
				a.Equal("invalid_name", evt.Data["code"], evt.Data["error"])
			})
		}
	}

	// A name with a zero-width non-joiner, which Persian needs, is fine.
	a := require.New(t)
	d.handleSetMyName(Command{
		ID:     "persian",
		Params: mustJSON(SetMyNameParams{Name: "\u0645\u06cc\u200c\u0631\u0648"}),
	})
	evt := rec.waitFor(t, func(e recordedEvent) bool {
		return e.ID == "persian"
	})
	a.Equal(EvtResponse, evt.Evt, "set_my_name: %v", evt.Data)
	d.mu.RLock()
	a.Empty(d.serverAddr, "a refused start_server was started")
	d.mu.RUnlock()
}
