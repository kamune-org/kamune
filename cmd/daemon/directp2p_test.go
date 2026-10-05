package main

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune"
)

// sendKCPOpen sends, from a new UDP socket bound to ip, a datagram that
// kcp-go takes as the first packet of a new session with conversation
// conv: a 24-byte KCP header. The datagrams of one host to one socket
// arrive in the order they were sent.
func sendKCPOpen(t *testing.T, ip string, dst *net.UDPAddr, conv uint32) {
	a := require.New(t)
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(ip)})
	a.NoError(err)
	t.Cleanup(func() { _ = conn.Close() })
	pkt := make([]byte, 24)
	binary.LittleEndian.PutUint32(pkt, conv)
	pkt[4] = 81 // IKCP_CMD_PUSH
	_, err = conn.WriteToUDP(pkt, dst)
	a.NoError(err)
}

// acceptedAddrs accepts sessions from l and sends their remote addresses
// on the channel it returns, until l is closed.
func acceptedAddrs(l kamune.Listener) <-chan net.Addr {
	accepted := make(chan net.Addr, 8)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			ra, _ := c.(interface{ RemoteAddr() net.Addr })
			accepted <- ra.RemoteAddr()
		}
	}()
	return accepted
}

// A direct p2p listener takes KCP sessions only from its peer's IP
// address: a session that a stranger opened first is never accepted.
func TestDirectP2PListenerAcceptsOnlyItsPeer(t *testing.T) {
	a := require.New(t)
	l, err := newDirectP2PListener("127.0.0.2:0", "127.0.0.4:9")
	a.NoError(err)
	t.Cleanup(func() { _ = l.Close() })

	sendKCPOpen(t, "127.0.0.1", l.Addr(), 1)
	sendKCPOpen(t, "127.0.0.4", l.Addr(), 2)

	select {
	case addr := <-acceptedAddrs(l):
		ua, ok := addr.(*net.UDPAddr)
		a.True(ok)
		a.Equal("127.0.0.4", ua.IP.String(), "accepted a stranger")
	case <-time.After(testEventTimeout):
		t.Fatal("the peer's session was not accepted")
	}
}
