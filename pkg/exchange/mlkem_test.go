package exchange

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMLKEM(t *testing.T) {
	a := require.New(t)

	// Peer1
	p1, err := NewMLKEM()
	a.NoError(err)
	a.NotNil(p1)
	pub := p1.MarshalPublicKey()

	// Peer2
	s1, ct, err := EncapsulateMLKEM(pub)
	a.NoError(err)
	a.NotNil(ct)
	a.NotNil(s1)

	// Peer 1
	s2, err := p1.Decapsulate(ct)
	a.NoError(err)
	a.NotNil(s2)

	a.Equal(s1, s2)
}
