package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xtaci/kcp-go/v5"
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

// TestP2PListener_AcceptDropsNonKCPFrames drives a peer that sends a
// raw UDP packet to the listener; the listener's kcp-go monitor
// reads it and (if it's a valid KCP frame) Accept returns a
// kamune.Conn. The packet we send is NOT a valid KCP frame, so
// the monitor drops it — we only assert that Accept blocks (no
// spurious errors). A full end-to-end KCP test is covered by
// the kamune library's own tests.
//
// This test exists primarily to lock in the listener's basic
// packet handling and lifecycle. The full KCP-handshake flow
// is exercised in production (and via the kamune library's
// integration tests).
func TestP2PListener_AcceptDropsNonKCPFrames(t *testing.T) {
	a := require.New(t)

	bc, err := NewBrokerClient()
	a.NoError(err)

	listener, err := newP2PListenerNoBroker(t, bc, "127.0.0.1:0")
	a.NoError(err)
	defer listener.Close()

	listenerUDPAddr := listener.Addr()
	a.NotNil(listenerUDPAddr)

	// Send a raw UDP packet to the listener. The kcp-go monitor
	// reads it, sees it's not a valid KCP frame, and drops it.
	// The listener's Accept should remain blocked.
	sender, err := net.DialUDP(
		"udp4", nil, listenerUDPAddr,
	)
	a.NoError(err)
	defer sender.Close()
	_, err = sender.Write([]byte("not a kcp frame"))
	a.NoError(err)

	// Give the monitor time to process the packet.
	time.Sleep(100 * time.Millisecond)

	// Accept should still be blocked (no conn to return).
	acceptDone := make(chan error, 1)
	go func() {
		_, err := listener.Accept()
		acceptDone <- err
	}()

	// Cancel the pending Accept by closing the listener; the
	// goroutine should return with an error.
	a.NoError(listener.Close())
	select {
	case err := <-acceptDone:
		a.Error(err)
	case <-time.After(2 * time.Second):
		t.Fatal("Accept did not return after Close")
	}
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
		ctx:        ctx,
		cancel:     cancel,
	}
	kcpL, err := kcp.ServeConn(nil, 0, 0, conn)
	if err != nil {
		_ = l.Close()
		return nil, err
	}
	l.kcp = kcpL
	return l, nil
}
