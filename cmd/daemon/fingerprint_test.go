package main

import (
	"testing"

	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/stretchr/testify/require"
)

// The local identity's fingerprint carries the numeric form, the one for
// people to compare, in fingerprint_changed and get_fingerprint, and
// set_fingerprint_format can choose it for display.
func TestFingerprintsCarryNumeric(t *testing.T) {
	a := require.New(t)
	d, rec := newTestDaemon(t, VerificationModeQuick, false)
	pub, err := d.store().PublicKey()
	a.NoError(err)
	numeric := fingerprint.Numeric(pub)

	d.loadIdentityAndHistory()
	evt := rec.waitFor(t, isEvent(EvtFingerprintChange))
	a.Equal(numeric, evt.Data["numeric"])

	d.handleSetFingerprintFormat(Command{
		ID: "format",
		Params: mustJSON(SetFingerprintFormatParams{
			Format: "numeric",
		}),
	})
	evt = rec.waitFor(t, func(e recordedEvent) bool { return e.ID == "format" })
	a.Equal(EvtResponse, evt.Evt, "set_fingerprint_format: %v", evt.Data)

	d.handleGetFingerprint(Command{ID: "get"})
	evt = rec.waitFor(t, func(e recordedEvent) bool { return e.ID == "get" })
	a.Equal(EvtResponse, evt.Evt)
	a.Equal(numeric, evt.Data["numeric"])
	a.Equal("numeric", evt.Data["format"])
	a.Equal(numeric, evt.Data["display"])
	a.Equal(fingerprint.Hex(pub), evt.Data["hex"])

	stored, err := d.store().GetSettings("daemon", "fingerprint_format")
	a.NoError(err)
	a.Equal("numeric", stored)
}
