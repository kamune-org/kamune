package kamune

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/pkg/attest"
)

func TestIntroduce(t *testing.T) {
	a := require.New(t)
	id := attest.Ed25519
	c1, c2 := net.Pipe()
	conn1, err := newConn(c1)
	a.NoError(err)
	conn2, err := newConn(c2)
	a.NoError(err)
	defer func() {
		a.NoError(conn1.Close())
		a.NoError(conn2.Close())
	}()
	attester1, err := id.NewAttest()
	a.NoError(err)
	attester2, err := id.NewAttest()
	a.NoError(err)

	go func() {
		err = sendIntroduction(conn1, attester1)
		a.NoError(err)
	}()
	remote, err := receiveIntroduction(conn2, id)
	a.NoError(err)
	a.Equal(attester1.PublicKey(), remote)

	go func() {
		err = sendIntroduction(conn2, attester2)
		a.NoError(err)
	}()
	remote, err = receiveIntroduction(conn1, id)
	a.NoError(err)
	a.Equal(attester2.PublicKey(), remote)
}
