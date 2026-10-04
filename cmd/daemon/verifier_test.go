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
			return e.Evt == EvtVerifyPeer && e.Data["peer_name"] == p.Name
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
		rejected := "Rejected peer " + p.Name + " without asking"
		evt := rec.waitFor(t, func(e recordedEvent) bool {
			msg, _ := e.Data["message"].(string)
			return e.Evt == EvtVerifyPeer && e.Data["peer_name"] == p.Name ||
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
		id, _, err := d.beginVerification(&storage.Peer{
			Name: name, PublicKey: newTestPeerKey(t),
		}, "", false, true)
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
