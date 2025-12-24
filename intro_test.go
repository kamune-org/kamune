package kamune

import (
	"crypto/rand"
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/pkg/attest"
)

func TestIntroduce(t *testing.T) {
	a := require.New(t)
	alg := attest.MLDSAAlgorithm
	c1, c2 := net.Pipe()
	conn1, err := newConn(c1)
	a.NoError(err)
	conn2, err := newConn(c2)
	a.NoError(err)
	defer func() {
		a.NoError(conn1.Close())
		a.NoError(conn2.Close())
	}()
	attester1, err := attest.NewAttester(alg)
	a.NoError(err)
	attester2, err := attest.NewAttester(alg)
	a.NoError(err)

	go func() {
		err = sendIntroduction(conn1, rand.Text(), attester1, alg)
		a.NoError(err)
	}()
	st2, route2, err := readSignedTransport(conn2)
	a.NoError(err)
	a.Equal(route2, RouteIdentity)
	peer, err := receiveIntroduction(st2)
	a.NoError(err)
	a.Equal(attester1.PublicKey(), peer.PublicKey)

	go func() {
		err = sendIntroduction(conn2, rand.Text(), attester2, alg)
		a.NoError(err)
	}()
	st1, route1, err := readSignedTransport(conn1)
	a.NoError(err)
	a.True(route1 == RouteIdentity || route1 == RouteInvalid)
	peer, err = receiveIntroduction(st1)
	a.NoError(err)
	a.Equal(attester2.PublicKey(), peer.PublicKey)
}
