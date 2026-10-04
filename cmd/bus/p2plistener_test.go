package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xtaci/kcp-go/v5"

	relaybroker "github.com/kamune-org/kamune/pkg/relayconn/broker"
)

// TestP2PListener_AcceptBlocksUntilClose verifies that Accept blocks
// indefinitely (until Close is called) when no peer connects.
func TestP2PListener_AcceptBlocksUntilClose(t *testing.T) {
	a := require.New(t)

	bc, err := NewBrokerClient()
	a.NoError(err)

	// newP2PListener will Echo+Register from the punch socket; we
	// don't run a fake broker so Echo will fail. To exercise
	// Accept-blocking behavior, build the listener manually without
	// the broker calls.
	listener, err := newP2PListenerNoBroker(t, bc, ":0")
	a.NoError(err)
	defer listener.Close()

	acceptDone := make(chan error, 1)
	go func() {
		_, err := listener.Accept()
		acceptDone <- err
	}()

	// Give Accept a moment to block.
	select {
	case err := <-acceptDone:
		t.Fatalf("Accept returned before Close: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	// Close should unblock Accept.
	a.NoError(listener.Close())
	select {
	case err := <-acceptDone:
		// Accept should return a closed-pipe / closed-network
		// error. We don't assert on the exact type — any error
		// is a successful "unblocked" signal.
		a.Error(err)
	case <-time.After(2 * time.Second):
		t.Fatal("Accept did not return after Close")
	}
}

// TestP2PListener_AcceptsOnlyMatchedPeer checks that the p2p listener
// keeps the broker's NOTIFY and a stray datagram from kcp-go, which would
// make sessions of them, and that on the broker's PEER_MATCHED it kicks
// the matched peer's address and takes that peer's KCP session.
func TestP2PListener_AcceptsOnlyMatchedPeer(t *testing.T) {
	a := require.New(t)
	app := newTestAppForP2P(t)
	token := bytes.Repeat([]byte{5}, 16)
	l, _, _, fb := startTestP2PServerOn(t, app, token, nil)

	// A stray datagram as long as a KCP header, from an address that
	// no broker matched.
	stray, err := net.DialUDP("udp4", nil, l.Addr())
	a.NoError(err)
	defer stray.Close()
	_, err = stray.Write(bytes.Repeat([]byte{1}, 32))
	a.NoError(err)

	dialer, err := net.ListenUDP(
		"udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
	)
	a.NoError(err)
	defer dialer.Close()
	dialerAddr := dialer.LocalAddr().(*net.UDPAddr)

	// The broker matches the listener with the dialer.
	sendNotify(t, fb, relaybroker.PeerMatchedPlaintext(
		token, bytes.Repeat([]byte{2}, 32),
		dialerAddr.IP, uint16(dialerAddr.Port),
	), l.Addr(), app.brokerClient.PublicKey())

	// The listener kicks the dialer's address from the punch socket.
	a.NoError(dialer.SetReadDeadline(time.Now().Add(testWait)))
	buf := make([]byte, 1500)
	_, src, err := dialer.ReadFromUDP(buf)
	a.NoError(err, "the listener sent no NAT kick to the matched peer")
	a.Equal(l.Addr().Port, src.Port)
	a.NoError(dialer.SetReadDeadline(time.Time{}))

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
		a.Equal(dialerAddr.String(), c.RemoteAddr().String())
		_ = got.(io.Closer).Close()
	case <-time.After(testWait):
		t.Fatal("the listener accepted no session from the matched peer")
	}
}

// TestP2PListener_HandleBrokerToken checks that the p2p listener expects
// a matched peer only on a PEER_MATCHED for a token it registers.
func TestP2PListener_HandleBrokerToken(t *testing.T) {
	token := bytes.Repeat([]byte{5}, 32)
	tests := []struct {
		name   string
		token  []byte
		expect bool
	}{
		{name: "registered token", token: token, expect: true},
		{
			name:  "other token",
			token: bytes.Repeat([]byte{6}, 32),
		},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			bc, err := NewBrokerClient()
			a.NoError(err)
			l, err := newP2PListenerNoBroker(t, bc, "127.0.0.1:0")
			a.NoError(err)
			defer l.Close()
			l.tokens = []listenerToken{{token: token}}

			peer := netip.AddrPortFrom(
				netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)}), 4000,
			)
			pkt, err := sealedNotify(relaybroker.PeerMatchedPlaintext(
				relaybroker.WireToken(tt.token),
				bytes.Repeat([]byte{2}, 32),
				net.IP(peer.Addr().AsSlice()), peer.Port(),
			), bc.PublicKey())
			a.NoError(err)
			l.handleBroker(pkt)
			// The filter takes any port from the matched IP.
			other := netip.AddrPortFrom(peer.Addr(), 4001)
			a.Equal(tt.expect, l.filter.admits(other))
		})
	}
}

// TestP2PListener_PeerMatchedWhileStarting checks that the p2p listener
// handles a PEER_MATCHED that kcp-go reads before kcp.ServeConn returns,
// as when the broker matches a dialer that already waits on the token as
// soon as the listener registers it.
func TestP2PListener_PeerMatchedWhileStarting(t *testing.T) {
	a := require.New(t)
	bc, err := NewBrokerClient()
	a.NoError(err)
	fb := newFakeBroker(t)
	loopback := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	conn, err := net.ListenUDP("udp4", loopback)
	a.NoError(err)
	dialer, err := net.ListenUDP("udp4", loopback)
	a.NoError(err)
	defer dialer.Close()
	dialerAddr := dialer.LocalAddr().(*net.UDPAddr)

	token := bytes.Repeat([]byte{5}, 16)
	ctx, cancel := context.WithCancel(context.Background())
	l := &p2pListener{
		broker:    bc,
		brokerUDP: fb.conn.LocalAddr().(*net.UDPAddr),
		token:     token,
		tokens:    []listenerToken{{token: token}},
		conn:      conn,
		kicking:   make(map[netip.AddrPort]struct{}),
		ctx:       ctx,
		cancel:    cancel,
	}
	defer l.Close()

	// The PEER_MATCHED waits on the punch socket before kcp-go reads it.
	sendNotify(t, fb, relaybroker.PeerMatchedPlaintext(
		token, bytes.Repeat([]byte{2}, 32),
		dialerAddr.IP, uint16(dialerAddr.Port),
	), l.Addr(), bc.PublicKey())

	// kcp.ServeConn returns only once the listener has kicked the
	// matched peer, which it does on reading the PEER_MATCHED.
	var kickErr error
	err = l.serveWith(func(
		block kcp.BlockCrypt, ds, ps int, pc net.PacketConn,
	) (*kcp.Listener, error) {
		kl, err := kcp.ServeConn(block, ds, ps, pc)
		if err != nil {
			return nil, err
		}
		kickErr = dialer.SetReadDeadline(time.Now().Add(testWait))
		if kickErr == nil {
			_, _, kickErr = dialer.ReadFromUDP(make([]byte, 1500))
		}
		return kl, nil
	})
	a.NoError(err)
	a.NoError(kickErr, "the listener sent no NAT kick to the matched peer")
	a.True(l.filter.admits(dialerAddr.AddrPort()))
}

// newP2PListenerNoBroker builds a p2pListener without going through the
// broker (no Echo, no Register). Used to test the Accept/Close lifecycle
// without a fake broker. The listener's kcp-go instance is still fully
// functional — it just doesn't have a broker registration.
func newP2PListenerNoBroker(
	t *testing.T, bc *BrokerClient, bindAddr string,
) (*p2pListener, error) {
	t.Helper()
	if bindAddr == "" {
		bindAddr = ":0"
	}
	udpAddr, err := net.ResolveUDPAddr("udp4", bindAddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	l := &p2pListener{
		bindAddr:   bindAddr,
		broker:     bc,
		brokerAddr: "",
		token:      nil,
		conn:       conn,
		kicking:    make(map[netip.AddrPort]struct{}),
		ctx:        ctx,
		cancel:     cancel,
	}
	if err := l.serve(); err != nil {
		_ = l.Close()
		return nil, err
	}
	return l, nil
}
