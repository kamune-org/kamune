package main

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xtaci/kcp-go/v5"
)

// TestDirectP2PListener_AcceptsOnlyPeer checks that the direct p2p
// listener keeps a datagram from an IP address other than the peer's
// from kcp-go, which would make a session of it, and takes the peer's
// session from a port other than the one it was given.
func TestDirectP2PListener_AcceptsOnlyPeer(t *testing.T) {
	a := require.New(t)
	// 127.0.0.2 is a loopback address on Linux but not on every
	// system.
	stray, err := net.ListenUDP(
		"udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2)},
	)
	if err != nil {
		t.Skipf("no second loopback address: %v", err)
	}
	defer stray.Close()

	l, err := newDirectP2PListener("127.0.0.1:0", "127.0.0.1:9")
	a.NoError(err)
	defer l.Close()

	_, err = stray.WriteToUDP(bytes.Repeat([]byte{1}, 32), l.Addr())
	a.NoError(err)

	dialer, err := net.ListenUDP(
		"udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
	)
	a.NoError(err)
	defer dialer.Close()
	sess, err := kcp.NewConn4(7, l.Addr(), nil, 0, 0, false, dialer)
	a.NoError(err)
	defer sess.Close()
	_, err = sess.Write([]byte("hello"))
	a.NoError(err)

	accepted := make(chan any, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			accepted <- err
			return
		}
		accepted <- c
	}()
	select {
	case got := <-accepted:
		c, ok := got.(interface{ RemoteAddr() net.Addr })
		a.True(ok, "Accept failed: %v", got)
		a.Equal(dialer.LocalAddr().String(), c.RemoteAddr().String())
		_ = got.(io.Closer).Close()
	case <-time.After(testWait):
		t.Fatal("the listener accepted no session from the peer")
	}
}
