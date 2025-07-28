package exchange

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestECDH(t *testing.T) {
	a := require.New(t)

	p1, err := NewECDH()
	a.NoError(err)
	a.NotNil(p1)

	p2, err := NewECDH()
	a.NoError(err)
	a.NotNil(p2)

	secretP1, err := p1.Exchange(p2.MarshalPublicKey())
	a.NoError(err)
	a.NotNil(secretP1)

	secretP2, err := p2.Exchange(p1.MarshalPublicKey())
	a.NoError(err)
	a.NotNil(secretP2)

	a.Equal(secretP1, secretP2)
}
