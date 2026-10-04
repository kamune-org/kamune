package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/fingerprint"
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

// TestDeleteHistoryOfLiveSession deletes the history of a session that
// is still open and checks that the session is closed first, so that no
// later message brings the history back.
func TestDeleteHistoryOfLiveSession(t *testing.T) {
	a := require.New(t)
	app, _ := newUnlockedApp(t, "secret")
	app.mu.Lock()
	app.verifMode = VerificationModeAutoAccept
	app.mu.Unlock()
	events := recordEvents(app)

	id, peer, _ := openPeerSession(t, app, false)
	_, err := peer.Send(
		kamune.Bytes([]byte("hi")), kamune.RouteExchangeMessages,
	)
	a.NoError(err)
	a.Eventually(func() bool {
		return len(events.named("message-received")) == 1
	}, testWait, time.Millisecond)

	a.NoError(app.DeleteHistorySession(id))

	a.Empty(app.GetSessions(), "the live session must be closed")
	sessions, err := app.store().ListSessions()
	a.NoError(err)
	a.NotContains(sessions, id)
	a.Empty(app.GetHistorySessions())
}

// TestDeleteWhenCompactionFails deletes a history and a peer while the
// database cannot be compacted, because its directory cannot be written,
// and checks that the record is deleted all the same and the user is
// warned that the deleted data may stay in the file.
func TestDeleteWhenCompactionFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes to a read-only directory")
	}
	cases := []struct {
		name   string
		delete func(t *testing.T, app *App)
	}{
		{"history", func(t *testing.T, app *App) {
			a := require.New(t)
			peer := newTestPeer(t, "carol")
			a.NoError(app.store().StorePeer(peer))
			a.NoError(app.store().CreateSession("S1", peer.PublicKey))
			app.RefreshHistory()
			a.Len(app.GetHistorySessions(), 1)

			a.NoError(app.DeleteHistorySession("S1"))
			a.Empty(app.GetHistorySessions())
			sessions, err := app.store().ListSessions()
			a.NoError(err)
			a.Empty(sessions)
		}},
		{"peer", func(t *testing.T, app *App) {
			a := require.New(t)
			key := fingerprint.Base64(newTestPubKey(t))
			a.NoError(app.AddPeer(key, "carol"))

			a.NoError(app.DeletePeer(key))
			a.Empty(app.ListKnownPeers())
			peers, err := app.store().ListPeers()
			a.NoError(err)
			a.Empty(peers)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			app, path := newUnlockedApp(t, "secret")
			var toasts []string
			app.onEvent = func(name string, data ...any) {
				if name == "toast" {
					toasts = append(toasts, data[0].(string))
				}
			}
			dir := filepath.Dir(path)
			a.NoError(os.Chmod(dir, 0o500))
			t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

			tc.delete(t, app)

			a.Len(toasts, 1)
			a.Contains(toasts[0], "may stay in the database file")
			a.NotNil(app.store(), "the database stays open")
		})
	}
}
