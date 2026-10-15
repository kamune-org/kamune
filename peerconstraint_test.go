package kamune

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPeerConstraint_AllowPeer(t *testing.T) {
	a := require.New(t)
	left, right := net.Pipe()
	t.Cleanup(func() {
		_ = left.Close()
		_ = right.Close()
	})
	key := []byte{1, 2, 3}
	wrapped := ExpectPeer(NewConn(left), key)
	c, ok := wrapped.(PeerConstraint)
	a.True(ok)
	a.True(c.AllowPeer(key))
	a.False(c.AllowPeer([]byte{9}))
	key[0] = 9
	a.True(c.AllowPeer([]byte{1, 2, 3}))
}
