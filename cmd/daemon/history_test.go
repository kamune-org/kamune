package main

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/kamune-org/kamune/pkg/storage"
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

// get_history_messages pages through a loaded history session with
// limit and offset: a limit of 0 or less means 500, and an offset out of
// range is clamped.
func TestGetHistoryMessagesPages(t *testing.T) {
	a := require.New(t)
	d, rec := newTestDaemon(t, VerificationModeQuick, false)
	const id = "history-session"
	const count = 5
	start := time.Now()
	for i := range count {
		sender := storage.SenderPeer
		if i%2 == 0 {
			sender = storage.SenderLocal
		}
		a.NoError(d.store().AddChatEntry(
			id, []byte(fmt.Sprintf("m%d", i)),
			start.Add(time.Duration(i)*time.Second), sender,
		))
	}
	d.loadHistorySessions()

	n := 0
	get := func(params GetHistoryMessagesParams) recordedEvent {
		t.Helper()
		n++
		cmdID := ID(fmt.Sprintf("get-%d", n))
		d.handleGetHistoryMessages(Command{
			ID: cmdID, Params: mustJSON(params),
		})
		return rec.waitFor(t, func(e recordedEvent) bool {
			return e.ID == cmdID
		})
	}

	// A session must be loaded before its messages are read.
	evt := get(GetHistoryMessagesParams{SessionID: id})
	a.Equal(EvtError, evt.Evt)
	a.Equal("history_not_loaded", evt.Data["code"])
	d.handleLoadHistory(Command{
		ID: "load", Params: mustJSON(LoadHistoryParams{SessionID: id}),
	})
	evt = rec.waitFor(t, func(e recordedEvent) bool { return e.ID == "load" })
	a.Equal(EvtResponse, evt.Evt, "load_history: %v", evt.Data)

	tests := []struct {
		name       string
		limit      int
		offset     int
		want       []string
		wantOffset int
		wantLimit  int
	}{
		{
			name: "defaults", wantLimit: 500,
			want: []string{"m0", "m1", "m2", "m3", "m4"},
		},
		{
			name: "first page", limit: 2, wantLimit: 2,
			want: []string{"m0", "m1"},
		},
		{
			name: "middle page", limit: 2, offset: 2,
			wantOffset: 2, wantLimit: 2, want: []string{"m2", "m3"},
		},
		{
			name: "last page", limit: 2, offset: 4,
			wantOffset: 4, wantLimit: 2, want: []string{"m4"},
		},
		{
			name: "offset past the end", limit: 2, offset: 9,
			wantOffset: count, wantLimit: 2, want: []string{},
		},
		{
			name: "negative offset", limit: 1, offset: -3,
			wantLimit: 1, want: []string{"m0"},
		},
		{
			name: "negative limit", limit: -1, offset: 3,
			wantOffset: 3, wantLimit: 500, want: []string{"m3", "m4"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			evt := get(GetHistoryMessagesParams{
				SessionID: id, Limit: tt.limit, Offset: tt.offset,
			})
			a.Equal(EvtResponse, evt.Evt, "get: %v", evt.Data)
			a.EqualValues(count, evt.Data["total"])
			a.EqualValues(tt.wantOffset, evt.Data["offset"])
			a.EqualValues(tt.wantLimit, evt.Data["limit"])

			msgs, ok := evt.Data["messages"].([]any)
			a.True(ok, "messages: %v", evt.Data["messages"])
			got := make([]string, 0, len(msgs))
			for _, m := range msgs {
				msg, ok := m.(map[string]any)
				a.True(ok)
				text, _ := msg["text"].(string)
				got = append(got, text)
				var i int
				_, err := fmt.Sscanf(text, "m%d", &i)
				a.NoError(err)
				a.Equal(i%2 == 0, msg["is_local"], "sender of %s", text)
				data, err := base64.StdEncoding.DecodeString(
					msg["data_base64"].(string),
				)
				a.NoError(err)
				a.Equal(text, string(data))
			}
			a.Equal(tt.want, got)
		})
	}
}
