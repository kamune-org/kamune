package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
	"github.com/stretchr/testify/require"
)

// pkixKey returns the PKIX encoding of the Ed25519 point raw, whether or
// not it is a valid key.
func pkixKey(t *testing.T, raw []byte) []byte {
	der, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(raw))
	require.New(t).NoError(err)
	return der
}

// add_peer and the token commands refuse a key that is not a valid
// Ed25519 key, while delete_peer still looks it up, so that a peer that
// was stored with such a key can be removed.
func TestAddPeerRefusesInvalidKeys(t *testing.T) {
	identity := make([]byte, ed25519.PublicKeySize)
	identity[0] = 1 // the identity point, of order 1
	garbage := make([]byte, 44)
	_, err := rand.Read(garbage)
	require.New(t).NoError(err)

	tests := []struct {
		name string
		key  []byte
		ok   bool
	}{
		{name: "valid", key: newTestPeerKey(t), ok: true},
		{name: "small order", key: pkixKey(t, identity)},
		{name: "not pkix", key: garbage},
	}
	d, rec := newTestDaemon(t, VerificationModeQuick, false)
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			b64 := fingerprint.Base64(tt.key)
			run := func(name string, handle func(Command), params any) recordedEvent {
				id := ID(fmt.Sprintf("%s-%d", name, i))
				handle(Command{ID: id, Params: mustJSON(params)})
				return rec.waitFor(t, func(e recordedEvent) bool {
					return e.ID == id
				})
			}

			evt := run("add", d.handleAddPeer, AddPeerParams{PublicKey: b64})
			_, parseErr := parsePeerPubB64ToRaw(b64)
			if tt.ok {
				a.Equal(EvtResponse, evt.Evt, "add_peer: %v", evt.Data)
				a.NoError(parseErr)
				return
			}
			a.Equal(EvtError, evt.Evt)
			a.Equal("invalid_peer_key", evt.Data["code"], evt.Data["error"])
			a.Error(parseErr)

			evt = run("delete", d.handleDeletePeer,
				DeletePeerParams{PublicKey: b64})
			a.NotEqual("invalid_peer_key", evt.Data["code"],
				"delete_peer refused a key it should look up")
		})
	}
}

// Names stored before the protocol limited them, such as one with a
// bidirectional override that is longer than the limit, go out made safe
// to show: in list_peers, get_peer and the history list.
func TestStoredLegacyNamesAreSanitized(t *testing.T) {
	a := require.New(t)
	d, rec := newTestDaemon(t, VerificationModeQuick, false)
	legacy := "Bob\u202egnp.exe" + strings.Repeat("x", 2000)
	key := newTestPeerKey(t)
	a.NoError(d.store().StorePeer(&storage.Peer{
		Name: legacy, PublicKey: key, FirstSeen: time.Now(),
	}))
	a.NoError(d.store().AddChatEntry(
		"SESSION", []byte("hi"), time.Now(), storage.SenderPeer,
	))
	a.NoError(d.store().SetSessionName("SESSION", legacy))
	d.loadHistorySessions()

	run := func(id ID, handle func(Command), params any) recordedEvent {
		handle(Command{ID: id, Params: mustJSON(params)})
		return rec.waitFor(t, func(e recordedEvent) bool { return e.ID == id })
	}
	var names []string
	evt := run("list", d.handleListPeers, struct{}{})
	peers, _ := evt.Data["peers"].([]any)
	a.Len(peers, 1)
	peer, _ := peers[0].(map[string]any)
	names = append(names, fmt.Sprint(peer["name"]))
	evt = run("get", d.handleGetPeer,
		GetPeerParams{PublicKey: fingerprint.Base64(key)})
	names = append(names, fmt.Sprint(evt.Data["name"]))
	evt = run("history", d.handleGetHistorySessions, struct{}{})
	sessions, _ := evt.Data["sessions"].([]any)
	a.Len(sessions, 1)
	session, _ := sessions[0].(map[string]any)
	names = append(names, fmt.Sprint(session["name"]))
	evt = run("info", d.handleGetSessionInfo,
		GetSessionInfoParams{SessionID: "SESSION"})
	names = append(names, fmt.Sprint(evt.Data["name"]))

	for _, name := range names {
		a.NoError(kamune.ValidatePeerName(name), "%q", name)
		a.True(strings.HasPrefix(name, "Bob\ufffdgnp.exe"), "%q", name)
	}
}
