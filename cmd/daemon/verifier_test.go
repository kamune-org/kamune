package main

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

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

	a.NoError(d.getVerifier()(d.store(), peer()))
	_, err = d.store().FindPeer(pub)
	a.Error(err, "auto-accepted peer was stored")

	d.mu.Lock()
	d.verifMode = VerificationModeQuick
	d.mu.Unlock()
	verdict := make(chan error, 1)
	go func() { verdict <- d.getVerifier()(d.store(), peer()) }()

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
				verdict <- d.getVerifier()(d.store(), &storage.Peer{
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
