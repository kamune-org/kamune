package main

import (
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
