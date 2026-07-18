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
	c1, c2 := net.Pipe()
	conn1 := newConn(c1)
	conn2 := newConn(c2)
	defer func() {
		a.NoError(conn1.Close())
		a.NoError(conn2.Close())
	}()
	attest1, err := attest.New()
	a.NoError(err)
	attest2, err := attest.New()
	a.NoError(err)

	var sendErr1 error
	done1 := make(chan struct{})
	go func() {
		defer close(done1)
		sendErr1 = sendIntroduction(conn1, attest1, rand.Text(), "1.0.0")
	}()
	st2, err := readSignedTransport(conn2)
	a.NoError(err)
	<-done1
	a.NoError(sendErr1)
	route2, err := routeFromST(st2)
	a.NoError(err)
	a.Equal(route2, RouteIdentity)
	peer, version, err := receiveIntroduction(st2)
	a.NoError(err)
	a.Equal(attest1.MarshalPublicKey(), peer.PublicKey)
	a.Equal("1.0.0", version)

	var sendErr2 error
	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		sendErr2 = sendIntroduction(conn2, attest2, rand.Text(), "1.0.0")
	}()
	st1, err := readSignedTransport(conn1)
	a.NoError(err)
	<-done2
	a.NoError(sendErr2)
	route1, err := routeFromST(st1)
	a.NoError(err)
	a.True(route1 == RouteIdentity || route1 == RouteInvalid)
	peer, version, err = receiveIntroduction(st1)
	a.NoError(err)
	a.Equal(attest2.MarshalPublicKey(), peer.PublicKey)
	a.Equal("1.0.0", version)
}
