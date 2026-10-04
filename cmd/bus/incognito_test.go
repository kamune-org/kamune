package main

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/storage"
)

// freeTCPAddr returns a loopback address whose port was free a moment
// ago, for a server that must bind the address itself.
func freeTCPAddr(t *testing.T) string {
	t.Helper()
	a := require.New(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	a.NoError(err)
	addr := ln.Addr().String()
	a.NoError(ln.Close())
	return addr
}

// newIncognitoApp returns an unlocked app in incognito mode that admits
// every peer.
func newIncognitoApp(t *testing.T) *App {
	t.Helper()
	app, _ := newUnlockedApp(t, "secret")
	require.New(t).True(app.SetIncognito(true))
	app.mu.Lock()
	app.verifMode = VerificationModeAutoAccept
	app.mu.Unlock()
	return app
}

func acceptAll(*storage.Storage, *storage.Peer) error { return nil }

func TestIncognitoDialLeavesNoSessionRecord(t *testing.T) {
	a := require.New(t)
	app := newIncognitoApp(t)
	addr, _ := startTestServer(t, "srv", func(tr *kamune.Transport) error {
		for {
			if _, _, err := tr.ReceivePayload(); err != nil {
				return nil
			}
		}
	})

	res, err := app.ConnectToServer(
		addr, "tcp", "", "", "", "", "", "", "", false, false,
	)
	a.NoError(err)
	sessions, err := app.store().ListSessions()
	a.NoError(err)
	a.Empty(sessions, "an incognito dial must not store its session")

	a.NoError(app.DisconnectSession(res.SessionID))
	sessions, err = app.store().ListSessions()
	a.NoError(err)
	a.Empty(sessions)
}

func TestIncognitoServerLeavesNoSessionRecord(t *testing.T) {
	a := require.New(t)
	app := newIncognitoApp(t)
	addr := freeTCPAddr(t)
	_, _, err := app.StartServer(
		addr, "tcp", "", "srv", "", "", "", false, false, "",
	)
	a.NoError(err)
	t.Cleanup(func() { _ = app.StopServer() })

	dialStore := openTestStorage(t)
	var tr *kamune.Transport
	a.Eventually(func() bool {
		d, err := kamune.NewDialer(
			addr, dialStore, acceptAll, kamune.DialWithTCP(),
		)
		if err != nil {
			return false
		}
		tr, err = d.Dial()
		return err == nil
	}, testWait, 10*time.Millisecond)
	t.Cleanup(func() { _ = tr.Close() })

	a.Eventually(func() bool {
		return len(app.GetSessions()) == 1
	}, testWait, time.Millisecond)
	sessions, err := app.store().ListSessions()
	a.NoError(err)
	a.Empty(sessions, "an incognito server must not store its sessions")
}

func TestSetIncognitoRestartsRunningServer(t *testing.T) {
	a := require.New(t)
	app, _ := newUnlockedApp(t, "secret")
	addr := freeTCPAddr(t)
	_, _, err := app.StartServer(
		addr, "tcp", "", "srv", "", "", "", false, false, "",
	)
	a.NoError(err)
	t.Cleanup(func() { _ = app.StopServer() })

	asked := 0
	answer := false
	app.confirmFn = func(string, string) bool {
		asked++
		return answer
	}

	a.False(app.SetIncognito(true), "declining the restart keeps the mode")
	a.Equal(1, asked)
	a.False(app.GetIncognito())

	answer = true
	a.True(app.SetIncognito(true))
	a.Equal(2, asked)
	a.True(app.GetIncognito())
	app.mu.RLock()
	running, serverIncognito := app.server != nil, app.serverIncognito
	app.mu.RUnlock()
	a.True(running, "the server must run again")
	a.True(serverIncognito, "the server must run in incognito mode")
}

func TestSetIncognitoKeepsStoppedServerStopped(t *testing.T) {
	a := require.New(t)
	app, _ := newUnlockedApp(t, "secret")
	addr := freeTCPAddr(t)
	_, _, err := app.StartServer(
		addr, "tcp", "", "srv", "", "", "", false, false, "",
	)
	a.NoError(err)
	t.Cleanup(func() { _ = app.StopServer() })

	// The server stops while the user is asked to restart it.
	app.confirmFn = func(string, string) bool {
		a.NoError(app.StopServer())
		return true
	}
	a.False(app.SetIncognito(true))
	a.False(app.GetIncognito())
	a.False(app.GetServerRunning(), "a stopped server must stay stopped")
}

func TestIncognitoFollowsSession(t *testing.T) {
	cases := []struct {
		name string
		// incognito is the mode the session starts in. It is toggled
		// once the session is live.
		incognito bool
	}{
		{"started in incognito mode", true},
		{"incognito mode turned on later", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			app, _ := newUnlockedApp(t, "secret")
			app.mu.Lock()
			app.verifMode = VerificationModeAutoAccept
			app.incognito = tc.incognito
			app.mu.Unlock()
			received := make(chan struct{}, 1)
			app.onEvent = func(name string, _ ...any) {
				if name == "message-received" {
					received <- struct{}{}
				}
			}

			send := make(chan string)
			t.Cleanup(func() { close(send) })
			addr, _ := startTestServer(t, "srv",
				func(tr *kamune.Transport) error {
					go func() {
						for text := range send {
							_, _ = tr.Send(
								kamune.Bytes([]byte(text)),
								kamune.RouteExchangeMessages,
							)
						}
					}()
					return readUntilEnd(tr)
				})
			res, err := app.ConnectToServer(
				addr, "tcp", "", "", "", "", "", "", "", false, false,
			)
			a.NoError(err)
			a.True(app.SetIncognito(!tc.incognito))

			a.NoError(app.SendMessage(res.SessionID, "hello"))
			send <- "hi"
			select {
			case <-received:
			case <-time.After(testWait):
				t.Fatal("the message did not arrive")
			}

			// Neither message is stored: a session keeps the mode it
			// started in, and no session stores messages while
			// incognito mode is on.
			history, err := app.store().GetChatHistory(res.SessionID)
			a.NoError(err)
			a.Empty(history)
		})
	}
}
