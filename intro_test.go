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

	var sendErr1 error
	done1 := make(chan struct{})
	go func() {
		defer close(done1)
		sendErr1 = sendIntroduction(conn1, rand.Text(), attester1, alg)
	}()
	st2, route2, err := readSignedTransport(conn2)
	a.NoError(err)
	<-done1
	a.NoError(sendErr1)
	a.Equal(route2, RouteIdentity)
	peer, err := receiveIntroduction(st2)
	a.NoError(err)
	a.Equal(attester1.PublicKey(), peer.PublicKey)

	var sendErr2 error
	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		sendErr2 = sendIntroduction(conn2, rand.Text(), attester2, alg)
	}()
	st1, route1, err := readSignedTransport(conn1)
	a.NoError(err)
	<-done2
	a.NoError(sendErr2)
	a.True(route1 == RouteIdentity || route1 == RouteInvalid)
	peer, err = receiveIntroduction(st1)
	a.NoError(err)
	a.Equal(attester2.PublicKey(), peer.PublicKey)
}
