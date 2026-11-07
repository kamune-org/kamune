package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune"
)

// A cancelled dial fails at once. The error wraps ErrHolePunchFailed and
// the context's error.
func TestDirectP2PDialCancelled(t *testing.T) {
	a := require.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_, err := directP2PDial(ctx, "127.0.0.1:9")
	a.ErrorIs(err, context.Canceled)
	a.ErrorIs(err, ErrHolePunchFailed)
	a.Less(time.Since(start), time.Second)
}

// A dial to a bound port that nobody reads fails within a second. The
// error wraps ErrHolePunchFailed and ErrUDPHandshakeTimeout.
func TestDirectP2PDialUnanswered(t *testing.T) {
	a := require.New(t)
	silent, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP: net.IPv4(127, 0, 0, 1),
	})
	a.NoError(err)
	t.Cleanup(func() { _ = silent.Close() })

	ctx, cancel := context.WithTimeout(
		context.Background(), 300*time.Millisecond,
	)
	defer cancel()
	start := time.Now()
	_, err = directP2PDial(ctx, silent.LocalAddr().String())
	a.Less(time.Since(start), time.Second)
	a.ErrorIs(err, ErrHolePunchFailed)
	a.ErrorIs(err, kamune.ErrUDPHandshakeTimeout)
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

// A direct p2p listener accepts a path only from its peer's IP. A
// stranger that dials first gets no path, and the peer's path is the
// one Accept returns.
func TestDirectP2PListenerAcceptsOnlyItsPeer(t *testing.T) {
	a := require.New(t)
	l, err := newDirectP2PListener("127.0.0.2:0", "127.0.0.4:9")
	if err != nil {
		t.Skipf("no second loopback address: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	stranger, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP: net.ParseIP("127.0.0.1"),
	})
	if err != nil {
		t.Skipf("no second loopback address: %v", err)
	}
	t.Cleanup(func() { _ = stranger.Close() })

	peer, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP: net.ParseIP("127.0.0.4"),
	})
	if err != nil {
		t.Skipf("no second loopback address: %v", err)
	}
	t.Cleanup(func() { _ = peer.Close() })

	accepted := acceptedAddrs(l)
	ctx, cancel := context.WithTimeout(
		context.Background(), 500*time.Millisecond,
	)
	defer cancel()
	_, err = kamune.DialUDP(ctx, stranger, l.Addr().AddrPort())
	a.Error(err)
	select {
	case addr := <-accepted:
		t.Fatalf("accepted a stranger: %v", addr)
	default:
	}

	dialCtx, dialCancel := context.WithTimeout(
		context.Background(), 5*time.Second,
	)
	defer dialCancel()
	dialed, err := kamune.DialUDP(dialCtx, peer, l.Addr().AddrPort())
	a.NoError(err)
	t.Cleanup(func() { _ = dialed.Close() })
	// Accept returns once the dialer sends its first DATA.
	a.NoError(dialed.SetDeadline(time.Now().Add(5 * time.Second)))
	wrote := make(chan error, 1)
	go func() { wrote <- dialed.WriteBytes([]byte{1}) }()

	select {
	case addr := <-accepted:
		got, ok := addrPortOf(addr)
		a.True(ok)
		want, ok := addrPortOf(peer.LocalAddr())
		a.True(ok)
		a.Equal(want, got)
	case <-time.After(testEventTimeout):
		t.Fatal("the peer's session was not accepted")
	}
	a.NoError(<-wrote)
}

// A listener on 127.0.0.1 whose peer is 127.0.0.1 accepts a dial from
// that address on another port.
func TestDirectP2PListenerAcceptsLoopbackPeer(t *testing.T) {
	a := require.New(t)
	l, err := newDirectP2PListener("127.0.0.1:0", "127.0.0.1:9")
	a.NoError(err)
	t.Cleanup(func() { _ = l.Close() })

	peer, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP: net.IPv4(127, 0, 0, 1),
	})
	a.NoError(err)
	t.Cleanup(func() { _ = peer.Close() })

	accepted := acceptedAddrs(l)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dialed, err := kamune.DialUDP(ctx, peer, l.Addr().AddrPort())
	a.NoError(err)
	t.Cleanup(func() { _ = dialed.Close() })
	// Accept returns once the dialer sends its first DATA.
	a.NoError(dialed.SetDeadline(time.Now().Add(5 * time.Second)))
	wrote := make(chan error, 1)
	go func() { wrote <- dialed.WriteBytes([]byte{1}) }()

	select {
	case addr := <-accepted:
		got, ok := addrPortOf(addr)
		a.True(ok)
		want, ok := addrPortOf(peer.LocalAddr())
		a.True(ok)
		a.Equal(want, got)
	case <-time.After(testEventTimeout):
		t.Fatal("the peer's session was not accepted")
	}
	a.NoError(<-wrote)
}

// Closing the listener leaves an accepted session able to exchange
// data. A second Close is harmless.
func TestDirectP2PListenerCloseKeepsSession(t *testing.T) {
	a := require.New(t)
	l, err := newDirectP2PListener("127.0.0.1:0", "127.0.0.1:9")
	a.NoError(err)
	t.Cleanup(func() { _ = l.Close() })

	peer, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP: net.IPv4(127, 0, 0, 1),
	})
	a.NoError(err)
	t.Cleanup(func() { _ = peer.Close() })

	accepted := make(chan kamune.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		accepted <- c
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dialed, err := kamune.DialUDP(ctx, peer, l.Addr().AddrPort())
	a.NoError(err)
	t.Cleanup(func() { _ = dialed.Close() })

	msg := []byte("still-open")
	deadline := time.Now().Add(5 * time.Second)
	a.NoError(dialed.SetDeadline(deadline))
	wrote := make(chan error, 1)
	go func() { wrote <- dialed.WriteBytes(msg) }()

	var serverConn kamune.Conn
	select {
	case serverConn = <-accepted:
	case <-time.After(testEventTimeout):
		t.Fatal("the peer's session was not accepted")
	}
	t.Cleanup(func() { _ = serverConn.Close() })

	a.NoError(l.Close())
	a.NoError(l.Close())

	a.NoError(serverConn.SetDeadline(deadline))
	got, err := serverConn.ReadBytes()
	a.NoError(err)
	a.Equal(msg, got)
	a.NoError(<-wrote)

	// A message sent after the close still crosses both ways.
	after := []byte("after-close")
	go func() { wrote <- dialed.WriteBytes(after) }()
	got, err = serverConn.ReadBytes()
	a.NoError(err)
	a.Equal(after, got)
	a.NoError(<-wrote)
	go func() { wrote <- serverConn.WriteBytes(after) }()
	got, err = dialed.ReadBytes()
	a.NoError(err)
	a.Equal(after, got)
	a.NoError(<-wrote)
}
