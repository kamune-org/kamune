package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
	"github.com/stretchr/testify/require"
)

func TestAutoAcceptedPeerIsStillVerifiedInQuickMode(t *testing.T) {
	a := require.New(t)
	d, rec := newTestDaemon(t, VerificationModeAutoAccept, false)
	stranger, _ := newTestDaemon(t, VerificationModeQuick, false)
	pub, err := stranger.store().PublicKey()
	a.NoError(err)
	peer := func() *storage.Peer {
		return &storage.Peer{Name: "stranger", PublicKey: pub}
	}

	a.NoError(d.inboundVerifier()(d.store(), peer()))
	_, err = d.store().FindPeer(pub)
	a.Error(err, "auto-accepted peer was stored")

	d.mu.Lock()
	d.verifMode = VerificationModeQuick
	d.mu.Unlock()
	verdict := make(chan error, 1)
	go func() { verdict <- d.inboundVerifier()(d.store(), peer()) }()

	evt := rec.waitFor(t, isEvent(EvtVerifyPeer))
	a.Equal(false, evt.Data["known"])
	id, ok := evt.Data["request_id"].(float64)
	a.True(ok)
	d.handleVerifyResponse(Command{
		ID: "reject",
		Params: mustJSON(VerifyResponseParams{
			RequestID: int64(id), Accepted: false,
		}),
	})
	a.ErrorIs(<-verdict, kamune.ErrVerificationFailed)
}

func TestUnknownVerificationModeIsStrict(t *testing.T) {
	for _, mode := range []VerificationMode{-1, 3, 7} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			a := require.New(t)
			d, rec := newTestDaemon(t, mode, false)
			stranger, _ := newTestDaemon(t, VerificationModeQuick, false)
			pub, err := stranger.store().PublicKey()
			a.NoError(err)
			verdict := make(chan error, 1)
			go func() {
				verdict <- d.inboundVerifier()(d.store(), &storage.Peer{
					Name: "stranger", PublicKey: pub,
				})
			}()

			evt := rec.waitFor(t, func(e recordedEvent) bool {
				msg, _ := e.Data["message"].(string)
				return e.Evt == EvtVerifyPeer || e.Evt == EvtLogEntry &&
					strings.Contains(msg, "Auto-accepted")
			})
			a.Equal(EvtVerifyPeer, evt.Evt, "peer was not verified")
			a.Equal("strict", evt.Data["mode"])
			id, ok := evt.Data["request_id"].(float64)
			a.True(ok)
			d.handleVerifyResponse(Command{
				Params: mustJSON(VerifyResponseParams{RequestID: int64(id)}),
			})
			a.ErrorIs(<-verdict, kamune.ErrVerificationFailed)
		})
	}
}

func TestStoredVerificationModeIsLoaded(t *testing.T) {
	tests := []struct {
		stored string
		want   VerificationMode
	}{
		{stored: "", want: VerificationModeQuick},
		{stored: "0", want: VerificationModeStrict},
		{stored: "2", want: VerificationModeAutoAccept},
		{stored: "3", want: VerificationModeStrict},
		{stored: "-1", want: VerificationModeStrict},
		{stored: "auto", want: VerificationModeStrict},
	}
	for _, tt := range tests {
		t.Run(strconv.Quote(tt.stored), func(t *testing.T) {
			a := require.New(t)
			d := newQuietDaemon()
			t.Cleanup(func() {
				d.cancel()
				d.closeStore()
			})
			openTestStorage(t, d, t.TempDir(), "kamune.db")
			a.NoError(d.store().SetSettings(
				"daemon", "verification_mode", tt.stored,
			))

			d.loadIdentityAndHistory()

			a.Equal(tt.want, d.verifMode)
		})
	}
}

// newTestPeerKey returns a fresh Ed25519 public key in PKIX form.
func newTestPeerKey(t *testing.T) []byte {
	a := require.New(t)
	pub, _, err := ed25519.GenerateKey(nil)
	a.NoError(err)
	der, err := x509.MarshalPKIXPublicKey(pub)
	a.NoError(err)
	return der
}

func TestPendingVerificationsAreCappedAndDeduped(t *testing.T) {
	a := require.New(t)
	d, rec := newTestDaemon(t, VerificationModeQuick, false)
	d.setStatus(StatusConnected, "Server running")

	peers := make([]*storage.Peer, maxPendingVerifications+1)
	for i := range peers {
		peers[i] = &storage.Peer{
			Name: fmt.Sprintf("peer-%d", i), PublicKey: newTestPeerKey(t),
		}
	}
	countPrompts := func() int {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		n := 0
		for _, e := range rec.events {
			if e.Evt == EvtVerifyPeer {
				n++
			}
		}
		return n
	}

	verdicts := make(chan error, maxPendingVerifications)
	for _, p := range peers[:maxPendingVerifications] {
		go func() { verdicts <- d.inboundVerifier()(d.store(), p) }()
	}
	var ids []int64
	for _, p := range peers[:maxPendingVerifications] {
		evt := rec.waitFor(t, func(e recordedEvent) bool {
			return e.Evt == EvtVerifyPeer && e.Data["claimed_name"] == p.Name
		})
		id, ok := evt.Data["request_id"].(float64)
		a.True(ok)
		ids = append(ids, int64(id))
	}
	d.mu.RLock()
	a.Equal(StatusVerifying, d.status)
	d.mu.RUnlock()

	// A second connection with a pending key is rejected without a prompt.
	err := d.inboundVerifier()(d.store(), &storage.Peer{
		Name: "again", PublicKey: peers[0].PublicKey,
	})
	a.ErrorIs(err, errVerificationPending)
	a.ErrorIs(err, kamune.ErrVerificationFailed)

	// So is any connection once the cap is reached.
	err = d.inboundVerifier()(d.store(), peers[maxPendingVerifications])
	a.ErrorIs(err, errTooManyVerifications)
	a.ErrorIs(err, kamune.ErrVerificationFailed)
	a.Equal(maxPendingVerifications, countPrompts())

	for _, id := range ids {
		d.handleVerifyResponse(Command{
			Params: mustJSON(VerifyResponseParams{RequestID: id}),
		})
	}
	for range ids {
		a.ErrorIs(<-verdicts, kamune.ErrVerificationFailed)
	}

	d.mu.RLock()
	status, msg := d.status, d.statusMsg
	d.mu.RUnlock()
	a.Equal(StatusConnected, status, "status was not put back")
	a.Equal("Server running", msg)

	// The key is no longer pending, so it is asked about again.
	verdict := make(chan error, 1)
	go func() { verdict <- d.inboundVerifier()(d.store(), peers[0]) }()
	last := slices.Max(ids)
	rec.waitFor(t, func(e recordedEvent) bool {
		id, _ := e.Data["request_id"].(float64)
		return e.Evt == EvtVerifyPeer && int64(id) > last
	})
	a.Equal(maxPendingVerifications+1, countPrompts())
	d.cancel()
	a.Error(<-verdict)
}

func TestFullVerificationSlotsLeaveKnownAndDialedPeers(t *testing.T) {
	a := require.New(t)
	d, rec := newTestDaemon(t, VerificationModeStrict, false)

	strangers := make([]*storage.Peer, maxPendingVerifications)
	for i := range strangers {
		strangers[i] = &storage.Peer{
			Name: fmt.Sprintf("stranger-%d", i), PublicKey: newTestPeerKey(t),
		}
	}
	friend := &storage.Peer{
		Name: "friend", PublicKey: newTestPeerKey(t), FirstSeen: time.Now(),
	}
	a.NoError(d.store().StorePeer(friend))

	// prompt runs v on p and returns the request ID of its prompt. Each
	// peer it gets has a name of its own.
	verdicts := make(chan error, maxPendingVerifications+4)
	prompt := func(v kamune.RemoteVerifier, p *storage.Peer) int64 {
		t.Helper()
		go func() { verdicts <- v(d.store(), p) }()
		rejected := identifyPeer(d.store(), p).logName() +
			" without asking"
		evt := rec.waitFor(t, func(e recordedEvent) bool {
			msg, _ := e.Data["message"].(string)
			return e.Evt == EvtVerifyPeer &&
				e.Data["claimed_name"] == p.Name ||
				e.Evt == EvtLogEntry && strings.Contains(msg, rejected)
		})
		a.Equal(EvtVerifyPeer, evt.Evt, "%s got no prompt", p.Name)
		id, ok := evt.Data["request_id"].(float64)
		a.True(ok)
		return int64(id)
	}

	var ids []int64
	for _, p := range strangers {
		ids = append(ids, prompt(d.inboundVerifier(), p))
	}
	err := d.inboundVerifier()(d.store(), &storage.Peer{
		Name: "one too many", PublicKey: newTestPeerKey(t),
	})
	a.ErrorIs(err, errTooManyVerifications)

	// A known peer that connects is still asked about, once per key.
	ids = append(ids, prompt(d.inboundVerifier(), friend))
	err = d.inboundVerifier()(d.store(), &storage.Peer{
		Name: "friend again", PublicKey: friend.PublicKey,
	})
	a.ErrorIs(err, errVerificationPending)

	// So is every peer the user dials, known or not, even one whose key
	// is pending on an inbound connection.
	for _, p := range []*storage.Peer{
		{Name: "dialed friend", PublicKey: friend.PublicKey},
		{Name: "dialed", PublicKey: newTestPeerKey(t)},
		{Name: "dialed stranger", PublicKey: strangers[0].PublicKey},
	} {
		ids = append(ids, prompt(d.outboundVerifier(), p))
	}

	for _, id := range ids {
		d.handleVerifyResponse(Command{
			Params: mustJSON(VerifyResponseParams{RequestID: id}),
		})
	}
	for range ids {
		a.ErrorIs(<-verdicts, kamune.ErrVerificationFailed)
	}
}

func TestVerificationRestoresTheLatestStatus(t *testing.T) {
	a := require.New(t)
	d, _ := newTestDaemon(t, VerificationModeQuick, false)
	begin := func(name string) int64 {
		t.Helper()
		peer := &storage.Peer{Name: name, PublicKey: newTestPeerKey(t)}
		id, _, err := d.beginVerification(
			peer, identifyPeer(nil, peer), "", true,
		)
		a.NoError(err)
		return id
	}
	status := func() (ConnectionStatus, string) {
		d.mu.RLock()
		defer d.mu.RUnlock()
		return d.status, d.statusMsg
	}

	d.setStatus(StatusConnected, "Server running")
	first := begin("first")
	second := begin("second")
	d.endVerification(first)
	// The first peer's session starts while the second is pending.
	d.setStatus(StatusConnected, "Connected to first")
	third := begin("third")
	s, _ := status()
	a.Equal(StatusVerifying, s)

	d.endVerification(second)
	d.endVerification(third)
	s, msg := status()
	a.Equal(StatusConnected, s)
	a.Equal("Connected to first", msg)
}

// set_verification_mode applies to a running server without restarting
// it: the live sessions, incoming and dialed, stay open, and the next
// peer that connects is verified in the new mode.
func TestSetVerificationModeKeepsSessions(t *testing.T) {
	a := require.New(t)
	server, serverRec := newTestDaemon(t, VerificationModeQuick, false)
	client, clientRec := newTestDaemon(t, VerificationModeQuick, false)
	trustPeer(t, server, client)
	trustPeer(t, client, server)

	addr := startTestServer(t, server, serverRec)
	id := dialTestServer(t, client, clientRec, addr)
	waitForSession(t, server, id)

	server.handleSetVerificationMode(Command{
		ID: "mode",
		Params: mustJSON(SetVerificationModeParams{
			Mode: int(VerificationModeStrict),
		}),
	})
	evt := serverRec.waitFor(t, func(e recordedEvent) bool {
		return e.ID == "mode"
	})
	a.Equal(EvtResponse, evt.Evt, "set_verification_mode: %v", evt.Data)

	server.mu.RLock()
	_, live := server.sessions[id]
	running := server.server != nil
	server.mu.RUnlock()
	a.True(live, "the server closed its session")
	a.True(running, "the server stopped")
	serverRec.mu.Lock()
	for _, e := range serverRec.events {
		a.NotEqual(EvtServerStopped, e.Evt, "the server was restarted")
	}
	serverRec.mu.Unlock()

	// Strict mode asks about a known peer too.
	client.handleDial(Command{
		ID: "dial2", Params: mustJSON(DialParams{Addr: addr}),
	})
	evt = serverRec.waitFor(t, isEvent(EvtVerifyPeer))
	a.Equal("strict", evt.Data["mode"])
	a.Equal(true, evt.Data["known"])
	reqID, ok := evt.Data["request_id"].(float64)
	a.True(ok)
	server.handleVerifyResponse(Command{
		ID: "accept",
		Params: mustJSON(VerifyResponseParams{
			RequestID: int64(reqID), Accepted: true,
		}),
	})
	evt = clientRec.waitFor(t, func(e recordedEvent) bool {
		return e.ID == "dial2" &&
			(e.Evt == EvtSessionStarted || e.Evt == EvtError)
	})
	a.Equal(EvtSessionStarted, evt.Evt, "dial failed: %v", evt.Data)

	client.mu.RLock()
	_, live = client.sessions[id]
	client.mu.RUnlock()
	a.True(live, "the first session was closed")
}

// A peer that the server does not know is admitted in Strict and Quick
// mode only when the user accepts it. An accepted peer is stored, except
// in incognito mode, and a rejected one is neither stored nor given a
// session.
func TestVerifyUnknownPeer(t *testing.T) {
	tests := []struct {
		name      string
		mode      VerificationMode
		incognito bool
		accept    bool
	}{
		{name: "strict accept", mode: VerificationModeStrict, accept: true},
		{name: "strict reject", mode: VerificationModeStrict},
		{name: "quick accept", mode: VerificationModeQuick, accept: true},
		{name: "quick reject", mode: VerificationModeQuick},
		{
			name: "incognito accept", mode: VerificationModeQuick,
			incognito: true, accept: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			server, serverRec := newTestDaemon(t, tt.mode, tt.incognito)
			client, clientRec := newTestDaemon(
				t, VerificationModeQuick, false,
			)
			trustPeer(t, client, server)
			clientPub, err := client.store().PublicKey()
			a.NoError(err)

			addr := startTestServer(t, server, serverRec)
			client.handleDial(Command{
				ID: "dial", Params: mustJSON(DialParams{Addr: addr}),
			})
			evt := serverRec.waitFor(t, isEvent(EvtVerifyPeer))
			a.Equal(false, evt.Data["known"])
			a.Equal(fingerprint.Numeric(clientPub), evt.Data["numeric"])
			wantMode := map[VerificationMode]string{
				VerificationModeStrict: "strict",
				VerificationModeQuick:  "quick",
			}[tt.mode]
			a.Equal(wantMode, evt.Data["mode"])
			id, ok := evt.Data["request_id"].(float64)
			a.True(ok)
			server.handleVerifyResponse(Command{
				ID: "answer",
				Params: mustJSON(VerifyResponseParams{
					RequestID: int64(id), Accepted: tt.accept,
				}),
			})
			evt = serverRec.waitFor(t, func(e recordedEvent) bool {
				return e.ID == "answer"
			})
			a.Equal(EvtResponse, evt.Evt, "verify_response: %v", evt.Data)

			evt = clientRec.waitFor(t, func(e recordedEvent) bool {
				return e.ID == "dial" &&
					(e.Evt == EvtSessionStarted || e.Evt == EvtError)
			})
			if !tt.accept {
				a.Equal(EvtError, evt.Evt, "rejected peer got a session")
				a.Equal("dial_failed", evt.Data["code"])
				server.mu.RLock()
				a.Empty(server.sessions)
				server.mu.RUnlock()
				_, err = server.store().FindPeer(clientPub)
				a.Error(err, "rejected peer was stored")
				return
			}
			a.Equal(EvtSessionStarted, evt.Evt, "dial failed: %v", evt.Data)
			sessionID, _ := evt.Data["session_id"].(string)
			waitForSession(t, server, sessionID)
			_, err = server.store().FindPeer(clientPub)
			if tt.incognito {
				a.Error(err, "incognito server stored the peer")
			} else {
				a.NoError(err, "accepted peer was not stored")
			}
		})
	}
}

// verify_response for a prompt that is over, because it timed out or
// was answered, fails with verification_not_found and changes nothing.
func TestLateVerifyResponseIsRefused(t *testing.T) {
	tests := []struct {
		name     string
		answered bool
	}{
		{name: "after the timeout"},
		{name: "after an answer", answered: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			d, rec := newTestDaemon(t, VerificationModeStrict, false)
			if !tt.answered {
				d.verifTimeout = 10 * time.Millisecond
			}
			peer := &storage.Peer{
				Name: "stranger", PublicKey: newTestPeerKey(t),
			}
			verdict := make(chan error, 1)
			go func() { verdict <- d.inboundVerifier()(d.store(), peer) }()
			evt := rec.waitFor(t, isEvent(EvtVerifyPeer))
			id, ok := evt.Data["request_id"].(float64)
			a.True(ok)
			answer := func(cmdID ID, accepted bool) recordedEvent {
				d.handleVerifyResponse(Command{
					ID: cmdID,
					Params: mustJSON(VerifyResponseParams{
						RequestID: int64(id), Accepted: accepted,
					}),
				})
				return rec.waitFor(t, func(e recordedEvent) bool {
					return e.ID == cmdID
				})
			}

			if tt.answered {
				evt = answer("reject", false)
				a.Equal(EvtResponse, evt.Evt)
			}
			select {
			case err := <-verdict:
				if tt.answered {
					a.ErrorIs(err, kamune.ErrVerificationFailed)
				} else {
					a.ErrorContains(err, "timed out")
				}
			case <-time.After(testEventTimeout):
				a.FailNow("the verifier did not return")
			}

			evt = answer("late", true)
			a.Equal(EvtError, evt.Evt)
			a.Equal("verification_not_found", evt.Data["code"])
			_, err := d.store().FindPeer(peer.PublicKey)
			a.Error(err, "a late answer stored the peer")
		})
	}
}

// The verifiers only decide whether to admit a peer; none of them stores
// it, so a peer whose handshake fails after the user accepted it does
// not become a known peer. rememberPeer stores a peer once its session
// is established, and only one that the user accepted as unknown.
func TestVerifiersDoNotStorePeers(t *testing.T) {
	tests := []struct {
		name       string
		mode       VerificationMode
		incognito  bool
		prompt     bool
		wantStored bool
	}{
		{
			name: "strict", mode: VerificationModeStrict,
			prompt: true, wantStored: true,
		},
		{
			name: "quick", mode: VerificationModeQuick,
			prompt: true, wantStored: true,
		},
		{name: "auto-accept", mode: VerificationModeAutoAccept},
		{
			name: "incognito", mode: VerificationModeQuick,
			incognito: true, prompt: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			d, rec := newTestDaemon(t, tt.mode, tt.incognito)
			peer := &storage.Peer{
				Name: "carol", PublicKey: newTestPeerKey(t),
			}
			verdict := make(chan error, 1)
			go func() { verdict <- d.inboundVerifier()(d.store(), peer) }()
			if tt.prompt {
				evt := rec.waitFor(t, isEvent(EvtVerifyPeer))
				id, ok := evt.Data["request_id"].(float64)
				a.True(ok)
				d.handleVerifyResponse(Command{
					Params: mustJSON(VerifyResponseParams{
						RequestID: int64(id), Accepted: true,
					}),
				})
			}
			a.NoError(<-verdict)
			_, err := d.store().FindPeer(peer.PublicKey)
			a.Error(err, "the verifier stored the peer")

			d.rememberPeer(d.store(), peer)
			_, err = d.store().FindPeer(peer.PublicKey)
			if tt.wantStored {
				a.NoError(err, "the established peer was not stored")
			} else {
				a.Error(err, "the peer was stored")
			}
		})
	}
}

// A session that a verifier did not ask the user about stores no peer:
// an auto-accepted one, and one whose verification was a rejection that
// rememberPeer never sees.
func TestRememberPeerNeedsAnAcceptance(t *testing.T) {
	a := require.New(t)
	d, _ := newTestDaemon(t, VerificationModeQuick, false)
	peer := &storage.Peer{Name: "dave", PublicKey: newTestPeerKey(t)}
	d.rememberPeer(d.store(), peer)
	_, err := d.store().FindPeer(peer.PublicKey)
	a.Error(err, "a peer nobody accepted was stored")

	// An acceptance that a later verdict on the key replaced is void.
	d.noteAdmitted(peer.PublicKey)
	a.NoError(d.createAutoAcceptVerifier()(d.store(), peer))
	d.rememberPeer(d.store(), peer)
	_, err = d.store().FindPeer(peer.PublicKey)
	a.Error(err, "a stale acceptance stored the peer")
}

// A client that dials a server it does not know asks the user, and
// stores the server once the session is established. A server in
// auto-accept mode stores none of its peers.
func TestDialedUnknownServerIsStoredOnceConnected(t *testing.T) {
	a := require.New(t)
	server, serverRec := newTestDaemon(t, VerificationModeAutoAccept, false)
	client, clientRec := newTestDaemon(t, VerificationModeQuick, false)
	serverPub, err := server.store().PublicKey()
	a.NoError(err)
	clientPub, err := client.store().PublicKey()
	a.NoError(err)

	addr := startTestServer(t, server, serverRec)
	client.handleDial(Command{
		ID: "dial", Params: mustJSON(DialParams{Addr: addr}),
	})
	evt := clientRec.waitFor(t, isEvent(EvtVerifyPeer))
	a.Equal(false, evt.Data["known"])
	id, ok := evt.Data["request_id"].(float64)
	a.True(ok)
	client.handleVerifyResponse(Command{
		Params: mustJSON(VerifyResponseParams{
			RequestID: int64(id), Accepted: true,
		}),
	})
	evt = clientRec.waitFor(t, func(e recordedEvent) bool {
		return e.ID == "dial" &&
			(e.Evt == EvtSessionStarted || e.Evt == EvtError)
	})
	a.Equal(EvtSessionStarted, evt.Evt, "dial failed: %v", evt.Data)
	sessionID, _ := evt.Data["session_id"].(string)
	waitForSession(t, server, sessionID)

	_, err = client.store().FindPeer(serverPub)
	a.NoError(err, "the accepted server was not stored")
	_, err = server.store().FindPeer(clientPub)
	a.Error(err, "the auto-accepted client was stored")
}

// stop_server ends the prompts of the peers whose handshakes the stopped
// server drops: they are rejected, so that no prompt outlives the server,
// and their dials fail.
func TestStopServerEndsPendingVerifications(t *testing.T) {
	a := require.New(t)
	server, serverRec := newTestDaemon(t, VerificationModeQuick, false)
	client, clientRec := newTestDaemon(t, VerificationModeQuick, false)
	trustPeer(t, client, server)

	addr := startTestServer(t, server, serverRec)
	client.handleDial(Command{
		ID: "dial", Params: mustJSON(DialParams{Addr: addr}),
	})
	evt := serverRec.waitFor(t, isEvent(EvtVerifyPeer))
	id, ok := evt.Data["request_id"].(float64)
	a.True(ok)

	server.handleStopServer(Command{ID: "stop"})
	server.verifMu.Lock()
	pending := len(server.verifRequests)
	server.verifMu.Unlock()
	a.Zero(pending, "a prompt outlived the server")

	server.handleVerifyResponse(Command{
		ID: "late",
		Params: mustJSON(VerifyResponseParams{
			RequestID: int64(id), Accepted: true,
		}),
	})
	evt = serverRec.waitFor(t, func(e recordedEvent) bool {
		return e.ID == "late"
	})
	a.Equal("verification_not_found", evt.Data["code"])
	evt = clientRec.waitFor(t, func(e recordedEvent) bool {
		return e.ID == "dial" &&
			(e.Evt == EvtSessionStarted || e.Evt == EvtError)
	})
	a.Equal(EvtError, evt.Evt, "the dial got a session")
}
