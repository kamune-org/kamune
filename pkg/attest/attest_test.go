package attest

import (
	"crypto/rand"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAttest(t *testing.T) {
	a := require.New(t)
	msg := []byte(rand.Text())

	e, err := New()
	a.NoError(err)
	a.NotNil(e)
	pub := e.MarshalPublicKey()
	sig, err := e.Sign(msg)
	a.NoError(err)
	a.NotNil(sig)

	id := Attest{}
	t.Run("valid signature", func(t *testing.T) {
		verified := id.Verify(pub, msg, sig)
		a.True(verified)
	})
	t.Run("invalid signature", func(t *testing.T) {
		sig := slices.Clone(sig)
		sig[0] ^= 0xFF

		verified := id.Verify(pub, msg, sig)
		a.False(verified)
	})
	t.Run("invalid hash", func(t *testing.T) {
		msg = append(msg, []byte("!")...)

		verified := id.Verify(pub, msg, sig)
		a.False(verified)
	})
	t.Run("invalid public key", func(t *testing.T) {
		another, err := New()
		a.NoError(err)
		verified := id.Verify(another.MarshalPublicKey(), msg, sig)
		a.False(verified)
	})
}
