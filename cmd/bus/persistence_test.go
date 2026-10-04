package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/storage"
)

// openPeerSession starts a session between app and a test peer, with the
// app dialing the peer's server, or with the peer dialing the app's
// server when serve is set. It returns the session ID, the peer's end of
// the session and the peer's public key.
func openPeerSession(
	t *testing.T, app *App, serve bool,
) (string, *kamune.Transport, []byte) {
	t.Helper()
	a := require.New(t)
	if serve {
		addr := freeTCPAddr(t)
		_, _, err := app.StartServer(
			addr, "tcp", "", "srv", "", "", "", false, false, "",
		)
		a.NoError(err)
		t.Cleanup(func() { _ = app.StopServer() })
		peerStore := openTestStorage(t)
		peerKey, err := peerStore.PublicKey()
		a.NoError(err)
		tr := dialTestServer(t, addr, peerStore)
		a.Eventually(func() bool {
			return liveSessionByID(app, tr.SessionID()) != nil
		}, testWait, time.Millisecond)
		return tr.SessionID(), tr, peerKey
	}

	// The peer's handler hands its end of the session to the test and
	// holds the session open until the test ends, so only the test reads
	// from it.
	peers := make(chan *kamune.Transport, 1)
	release := make(chan struct{})
	addr, peerKey := startTestServer(t, "srv",
		func(tr *kamune.Transport) error {
			peers <- tr
			<-release
			return nil
		})
	t.Cleanup(func() { close(release) })
	res, err := app.ConnectToServer(
		addr, "tcp", "", "", "", "", "", "", "", false, false, "",
	)
	a.NoError(err)
	select {
	case tr := <-peers:
		return res.SessionID, tr, peerKey
	case <-time.After(testWait):
		a.FailNow("the peer's handler did not start")
		return "", nil, nil
	}
}

// TestSessionPersistence checks what a session leaves in storage, for a
// session the app dials and one its server accepts: with incognito mode
// off, the session record, the messages sent each way and the peer; with
// it on, none of them.
func TestSessionPersistence(t *testing.T) {
	cases := []struct {
		name      string
		serve     bool
		incognito bool
	}{
		{"dialed", false, false},
		{"dialed in incognito mode", false, true},
		{"served", true, false},
		{"served in incognito mode", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			app, _ := newUnlockedApp(t, "secret")
			app.mu.Lock()
			app.verifMode = VerificationModeAutoAccept
			app.incognito = tc.incognito
			app.mu.Unlock()
			events := recordEvents(app)

			id, peer, peerKey := openPeerSession(t, app, tc.serve)

			_, err := peer.Send(
				kamune.Bytes([]byte("hi")), kamune.RouteExchangeMessages,
			)
			a.NoError(err)
			a.Eventually(func() bool {
				return len(events.named("message-received")) == 1
			}, testWait, time.Millisecond)
			a.NoError(app.SendMessage(id, "hello"))
			a.Equal("hello", receiveChat(t, peer))

			store := app.store()
			sessions, err := store.ListSessions()
			a.NoError(err)
			history, err := store.GetChatHistory(id)
			a.NoError(err)
			_, peerErr := store.FindPeer(peerKey)

			if tc.incognito {
				a.NotContains(sessions, id)
				a.Empty(history)
				a.Error(peerErr, "an incognito session must not store its peer")
				return
			}
			a.Contains(sessions, id)
			a.Len(history, 2)
			a.Equal("hi", string(history[0].Data))
			a.Equal(storage.SenderPeer, history[0].Sender)
			a.Equal("hello", string(history[1].Data))
			a.Equal(storage.SenderLocal, history[1].Sender)
			a.NoError(peerErr, "an established session stores its peer")
		})
	}
}
