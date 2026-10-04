package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/storage"
	"github.com/stretchr/testify/require"
)

// heapInUse returns the bytes of live heap objects after a collection.
func heapInUse() int64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return int64(m.HeapAlloc)
}

func TestLiveSessionKeepsNoMessagesInMemory(t *testing.T) {
	a := require.New(t)
	d, _ := newTestDaemon(t, VerificationModeQuick, false)
	const (
		sessionID = "QWERTYUIOPASDFGHJKLZXCVB"
		entries   = 96
		size      = 60 << 10
	)
	store := d.store()
	payload := make([]byte, size)
	for i := range entries {
		payload[0] = byte(i)
		a.NoError(store.AddChatEntry(
			sessionID, payload, time.Now(), storage.SenderPeer,
		))
	}

	// Leftover goroutines from other tests can change the heap while a
	// round runs, but not by the same amount in every round, whereas a
	// session that keeps its history grows it by the same amount each
	// time. The smallest growth of three rounds is compared.
	var grown int64
	for round := range 3 {
		session := &liveSession{ID: sessionID, LastActivity: time.Now()}
		before := heapInUse()
		d.loadChatHistory(session)
		for range entries {
			session.countMessage()
		}
		if g := heapInUse() - before; round == 0 || g < grown {
			grown = g
		}
		a.Equal(2*entries, d.sessionInfo(session).MsgCount)
		runtime.KeepAlive(session)
	}

	// The history is 5.6 MiB; a copy of it in memory would show here.
	a.Less(grown, int64(4<<20), "session keeps its history in memory")
}

// waitForCount waits until rec has n events that match accepts, and
// returns them in the order they were emitted.
func waitForCount(
	t *testing.T, rec *eventRecorder, n int, match func(recordedEvent) bool,
) []recordedEvent {
	t.Helper()
	deadline := time.After(testEventTimeout)
	for {
		var got []recordedEvent
		rec.mu.Lock()
		for _, e := range rec.events {
			if match(e) {
				got = append(got, e)
			}
		}
		rec.mu.Unlock()
		if len(got) >= n {
			return got
		}
		select {
		case <-rec.changed:
		case <-deadline:
			t.Fatalf("timed out waiting for %d events, got %d", n, len(got))
		}
	}
}

func TestSendMessageKeepsCommandOrder(t *testing.T) {
	a := require.New(t)
	server, serverRec := newTestDaemon(t, VerificationModeQuick, false)
	client, clientRec := newTestDaemon(t, VerificationModeQuick, false)
	trustPeer(t, server, client)
	trustPeer(t, client, server)
	addr := startTestServer(t, server, serverRec)
	id := dialTestServer(t, client, clientRec, addr)

	const n = 40
	var want []string
	for i := range n {
		text := fmt.Sprintf("m%02d", i)
		want = append(want, text)
		client.handleSendMessage(Command{
			ID: ID(text),
			Params: mustJSON(SendMessageParams{
				SessionID:  id,
				DataBase64: base64.StdEncoding.EncodeToString([]byte(text)),
			}),
		})
	}

	var sent []string
	for _, e := range waitForCount(t, clientRec, n, isEvent(EvtMessageSent)) {
		sent = append(sent, string(e.ID))
	}
	a.Equal(want, sent, "message_sent order")

	var received []string
	for _, e := range waitForCount(
		t, serverRec, n, isEvent(EvtMessageReceived),
	) {
		data, err := base64.StdEncoding.DecodeString(
			e.Data["data_base64"].(string),
		)
		a.NoError(err)
		received = append(received, string(data))
	}
	a.Equal(want, received, "received order")

	for name, d := range map[string]*Daemon{
		"client": client, "server": server,
	} {
		entries, err := d.store().GetChatHistory(id)
		a.NoError(err)
		var stored []string
		for _, e := range entries {
			stored = append(stored, string(e.Data))
		}
		a.Equal(want, stored, "%s history order", name)
		a.Equal(n, d.sessionInfo(waitForSession(t, d, id)).MsgCount, name)
	}
}

// A message that cannot be saved to history is still sent and received,
// and each side reports history_save_failed for it.
func TestFailedHistorySaveIsReported(t *testing.T) {
	a := require.New(t)
	server, serverRec := newTestDaemon(t, VerificationModeQuick, false)
	client, clientRec := newTestDaemon(t, VerificationModeQuick, false)
	trustPeer(t, server, client)
	trustPeer(t, client, server)
	addr := startTestServer(t, server, serverRec)
	id := dialTestServer(t, client, clientRec, addr)
	waitForSession(t, server, id)

	// Close both stores under the daemons, so that every save fails.
	for _, d := range []*Daemon{server, client} {
		a.NoError(d.store().Close())
	}
	client.handleSendMessage(Command{
		ID: "send",
		Params: mustJSON(SendMessageParams{
			SessionID:  id,
			DataBase64: base64.StdEncoding.EncodeToString([]byte("hi")),
		}),
	})

	clientRec.waitFor(t, isEvent(EvtMessageSent))
	serverRec.waitFor(t, isEvent(EvtMessageReceived))
	for _, rec := range []*eventRecorder{clientRec, serverRec} {
		evt := rec.waitFor(t, isEvent(EvtHistorySaveFailed))
		a.Equal(id, evt.Data["session_id"])
		a.NotEmpty(evt.Data["error"])
	}
}

func TestSendErrorReason(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "partial frame",
			err: fmt.Errorf("writing: %w",
				fmt.Errorf("%w: partial frame", kamune.ErrConnClosed)),
			want: "connection_lost",
		},
		{
			name: "too large",
			err:  fmt.Errorf("serializing: %w", kamune.ErrMessageTooLarge),
			want: "message_too_large",
		},
		{
			name: "over the relay's limit",
			err:  fmt.Errorf("writing: %w", exchange.ErrFrameTooLarge),
			want: "message_too_large",
		},
		{name: "other", err: errors.New("write deadline"), want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.New(t).Equal(tt.want, sendErrorReason(tt.err))
		})
	}
}

// A message that is too large fails with reason message_too_large and
// leaves the session usable; a send on a connection that is gone fails
// with reason connection_lost.
func TestSendFailureReasons(t *testing.T) {
	a := require.New(t)
	server, serverRec := newTestDaemon(t, VerificationModeQuick, false)
	client, clientRec := newTestDaemon(t, VerificationModeQuick, false)
	trustPeer(t, server, client)
	trustPeer(t, client, server)
	addr := startTestServer(t, server, serverRec)
	id := dialTestServer(t, client, clientRec, addr)

	send := func(cmdID ID, data []byte) recordedEvent {
		t.Helper()
		client.handleSendMessage(Command{
			ID: cmdID,
			Params: mustJSON(SendMessageParams{
				SessionID:  id,
				DataBase64: base64.StdEncoding.EncodeToString(data),
			}),
		})
		return clientRec.waitFor(t, func(e recordedEvent) bool {
			return e.ID == cmdID
		})
	}
	evt := send("large", make([]byte, 70000))
	a.Equal(EvtError, evt.Evt)
	a.Equal("send_message_failed", evt.Data["code"])
	a.Equal("message_too_large", evt.Data["reason"], evt.Data["error"])
	evt = send("small", []byte("hi"))
	a.Equal(EvtMessageSent, evt.Evt, "send after a large message: %v",
		evt.Data)

	session := waitForSession(t, server, id)
	a.NoError(session.snapshotTransport().CloseAbort())
	server.sendMessage(Command{ID: "lost"}, session, id, []byte("hi"))
	evt = serverRec.waitFor(t, func(e recordedEvent) bool {
		return e.ID == "lost"
	})
	a.Equal(EvtError, evt.Evt)
	a.Equal("connection_lost", evt.Data["reason"], evt.Data["error"])
}
