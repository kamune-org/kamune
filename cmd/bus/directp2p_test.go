package main

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune"
)

// TestDirectP2PListener_AcceptsOnlyPeer checks that a stranger gets no
// path, and that the peer is accepted from a port of its own.
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

	l := listenDirectPeer(t)
	ctx, cancel := context.WithTimeout(
		context.Background(), 500*time.Millisecond,
	)
	defer cancel()
	_, err = kamune.DialUDP(ctx, stray, directListenerPort(t, l))
	a.Error(err)

	assertAcceptedPeer(t, l)
}

// TestDirectP2PListener_AcceptsPeer checks the same peer accept on a
// system that cannot bind 127.0.0.2, such as macOS.
func TestDirectP2PListener_AcceptsPeer(t *testing.T) {
	assertAcceptedPeer(t, listenDirectPeer(t))
}

// TestDirectP2PDialUnanswered checks that a dial to a bound port that
// never reads fails with the path handshake timeout, inside a second.
func TestDirectP2PDialUnanswered(t *testing.T) {
	a := require.New(t)
	silent, err := net.ListenUDP(
		"udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
	)
	a.NoError(err)
	defer silent.Close()

	ctx, cancel := context.WithTimeout(
		context.Background(), 300*time.Millisecond,
	)
	defer cancel()
	start := time.Now()
	_, err = directP2PDial(ctx, silent.LocalAddr().String())
	a.Error(err)
	a.ErrorIs(err, kamune.ErrUDPHandshakeTimeout)
	a.Less(time.Since(start), time.Second)
}

// TestDirectP2PDialCancelled checks that an already cancelled context
// fails at once with context.Canceled.
func TestDirectP2PDialCancelled(t *testing.T) {
	a := require.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	_, err := directP2PDial(ctx, "127.0.0.1:9")
	a.ErrorIs(err, context.Canceled)
	a.Less(time.Since(start), time.Second)
}

// TestDirectP2PListener_CloseKeepsSession checks that closing the
// listener, twice, leaves an accepted session able to pass one message.
func TestDirectP2PListener_CloseKeepsSession(t *testing.T) {
	a := require.New(t)
	l := listenDirectPeer(t)
	_, peer, srv := dialDirectPeer(t, l)

	a.NoError(l.Close())
	a.NoError(l.Close())

	deadline := time.Now().Add(testWait)
	a.NoError(peer.SetDeadline(deadline))
	a.NoError(srv.SetDeadline(deadline))
	msg := []byte("alive")
	_, err := connBytes(t, peer).Write(msg)
	a.NoError(err)
	buf := make([]byte, len(msg))
	_, err = io.ReadFull(connBytes(t, srv), buf)
	a.NoError(err)
	a.Equal(msg, buf)
}

func listenDirectPeer(t *testing.T) *directP2PListener {
	t.Helper()
	l, err := newDirectP2PListener("127.0.0.1:0", "127.0.0.1:9")
	require.New(t).NoError(err)
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func directListenerPort(t *testing.T, l *directP2PListener) netip.AddrPort {
	t.Helper()
	ap, ok := addrPortOf(l.Addr())
	require.New(t).True(ok)
	return ap
}

func assertAcceptedPeer(t *testing.T, l *directP2PListener) {
	t.Helper()
	a := require.New(t)
	dialer, _, srv := dialDirectPeer(t, l)
	got, ok := srv.(interface{ RemoteAddr() net.Addr })
	a.True(ok)
	a.Equal(dialer.LocalAddr().String(), got.RemoteAddr().String())
}

// dialDirectPeer dials l from 127.0.0.1 on its own port and returns the
// dialer's socket, the dialed conn and the accepted conn.
func dialDirectPeer(
	t *testing.T, l *directP2PListener,
) (*net.UDPConn, kamune.Conn, kamune.Conn) {
	t.Helper()
	a := require.New(t)
	ap := directListenerPort(t, l)
	dialer, err := net.ListenUDP(
		"udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
	)
	a.NoError(err)

	accepted := make(chan kamune.Conn, 1)
	errc := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			errc <- err
			return
		}
		accepted <- c
	}()

	ctx, cancel := context.WithTimeout(context.Background(), testWait)
	defer cancel()
	peer, err := kamune.DialUDP(ctx, dialer, ap)
	if err != nil {
		_ = dialer.Close()
		a.NoError(err)
	}
	t.Cleanup(func() { _ = peer.Close() })

	// Accept returns once the first DATA opens the path. The path
	// handshake alone leaves it half-open.
	deadline := time.Now().Add(testWait)
	a.NoError(peer.SetDeadline(deadline))
	_, err = connBytes(t, peer).Write([]byte{1})
	a.NoError(err)

	var srv kamune.Conn
	select {
	case srv = <-accepted:
	case err := <-errc:
		t.Fatalf("Accept: %v", err)
	case <-time.After(testWait):
		t.Fatal("the listener accepted no session from the peer")
	}
	t.Cleanup(func() { _ = srv.Close() })
	a.NoError(srv.SetDeadline(deadline))
	var opened [1]byte
	_, err = io.ReadFull(connBytes(t, srv), opened[:])
	a.NoError(err)
	a.Equal(byte(1), opened[0])
	return dialer, peer, srv
}

func connBytes(t *testing.T, c kamune.Conn) io.ReadWriter {
	t.Helper()
	rw, ok := c.(io.ReadWriter)
	require.New(t).True(ok)
	return rw
}
