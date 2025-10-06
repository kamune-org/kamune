package attest

import (
	"crypto/rand"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	_ Attester   = Ed25519{}
	_ Identifier = Ed25519{}
	_ PublicKey  = Ed25519PublicKey{}
)

func TestEd25519(t *testing.T) {
	a := require.New(t)
	msg := []byte(rand.Text())

	e, err := newEd25519DSA()
	a.NoError(err)
	a.NotNil(e)
	pub := e.PublicKey()
	a.NotNil(pub)
	sig, err := e.Sign(msg)
	a.NoError(err)
	a.NotNil(sig)

	id := Ed25519{}
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
		another, err := newEd25519DSA()
		a.NoError(err)
		verified := id.Verify(another.PublicKey(), msg, sig)
		a.False(verified)
	})
}
