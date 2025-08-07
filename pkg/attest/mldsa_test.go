package attest

import (
	"crypto/rand"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMLDSA(t *testing.T) {
	a := require.New(t)
	msg := []byte(rand.Text())

	m, err := newMLDSA()
	a.NoError(err)
	a.NotNil(m)
	pub := m.PublicKey()
	a.NotNil(pub)
	sig, err := m.Sign(msg)
	a.NoError(err)
	a.NotNil(sig)

	attestation := MLDSA

	t.Run("valid signature", func(t *testing.T) {
		verified := attestation.Verify(pub, msg, sig)
		a.True(verified)
	})
	t.Run("invalid signature", func(t *testing.T) {
		sig := slices.Clone(sig)
		sig[0] ^= 0xDD

		verified := attestation.Verify(pub, msg, sig)
		a.False(verified)
	})
	t.Run("invalid hash", func(t *testing.T) {
		msg = append(msg, []byte("!")...)

		verified := attestation.Verify(pub, msg, sig)
		a.False(verified)
	})
	t.Run("invalid public key", func(t *testing.T) {
		another, err := newMLDSA()
		a.NoError(err)
		verified := attestation.Verify(another.PublicKey(), msg, sig)
		a.False(verified)
	})
}
