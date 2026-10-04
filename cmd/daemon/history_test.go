package main

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

// delete_history_session refuses a session that is still open, whose
// next message would start its history again, and deletes the history
// once the session is closed.
func TestDeleteHistoryOfLiveSession(t *testing.T) {
	a := require.New(t)
	server, serverRec := newTestDaemon(t, VerificationModeQuick, false)
	client, clientRec := newTestDaemon(t, VerificationModeQuick, false)
	trustPeer(t, server, client)
	trustPeer(t, client, server)
	addr := startTestServer(t, server, serverRec)
	id := dialTestServer(t, client, clientRec, addr)

	client.handleSendMessage(Command{
		ID: "send",
		Params: mustJSON(SendMessageParams{
			SessionID:  id,
			DataBase64: base64.StdEncoding.EncodeToString([]byte("hi")),
		}),
	})
	clientRec.waitFor(t, isEvent(EvtMessageSent))

	run := func(cmd ID, handle func(Command), params any) recordedEvent {
		handle(Command{ID: cmd, Params: mustJSON(params)})
		return clientRec.waitFor(t, func(e recordedEvent) bool {
			return e.ID == cmd
		})
	}
	params := MapS{"session_id": id}

	evt := run("delete", client.handleDeleteHistorySession, params)
	a.Equal(EvtError, evt.Evt)
	a.Equal("session_active", evt.Data["code"], evt.Data["error"])
	entries, err := client.store().GetChatHistory(id)
	a.NoError(err)
	a.Len(entries, 1)

	evt = run("close", client.handleCloseSession, params)
	a.Equal(EvtResponse, evt.Evt, "close failed: %v", evt.Data)
	evt = run("delete-closed", client.handleDeleteHistorySession, params)
	a.Equal(EvtResponse, evt.Evt, "delete failed: %v", evt.Data)
	entries, err = client.store().GetChatHistory(id)
	a.NoError(err)
	a.Empty(entries)
}
