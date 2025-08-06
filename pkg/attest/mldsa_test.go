package attest_test

import (
	"crypto/rand"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hossein1376/kamune/pkg/attest"
)

func TestMLDSA(t *testing.T) {
	a := require.New(t)
	msg := []byte(rand.Text())

	m, err := attest.NewMLDSA()
	a.NoError(err)
	a.NotNil(m)
	pub := m.PublicKey()
	a.NotNil(pub)
	sig, err := m.Sign(msg, nil)
	a.NoError(err)
	a.NotNil(sig)

	t.Run("valid signature", func(t *testing.T) {
		verified := attest.Verify(pub, msg, sig)
		a.True(verified)
	})
	t.Run("invalid signature", func(t *testing.T) {
		sig := slices.Clone(sig)
		sig[0] ^= 0xDD

		verified := attest.Verify(pub, msg, sig)
		a.False(verified)
	})
	t.Run("invalid hash", func(t *testing.T) {
		msg = append(msg, []byte("!")...)

		verified := attest.Verify(pub, msg, sig)
		a.False(verified)
	})
	t.Run("invalid public key", func(t *testing.T) {
		another, err := attest.NewMLDSA()
		a.NoError(err)
		verified := attest.Verify(another.PublicKey(), msg, sig)
		a.False(verified)
	})
}
