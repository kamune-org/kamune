package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/xtaci/kcp-go/v5"
)

// directP2PListener is a kamune.Listener that accepts inbound KCP connections
// from a peer whose address is known upfront. It sends a NAT-kick burst to
// the peer's address to open the local NAT mapping, then waits for the peer's
// KCP SYN on the same socket. Used for UDP hole punching without a broker.
type directP2PListener struct {
	conn      *net.UDPConn
	kcp       *kcp.Listener
	peerAddr  *net.UDPAddr
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
	closeErr  error
}

// newDirectP2PListener creates a listener that binds to listenAddr, starts a
// KCP listener on the same socket, and sends a NAT-kick burst to peerAddr
// to open the local NAT mapping. Both peers must be online simultaneously.
func newDirectP2PListener(listenAddr, peerAddr string) (*directP2PListener, error) {
	udpAddr, err := net.ResolveUDPAddr("udp4", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve listen addr: %w", err)
	}
	conn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("bind punch socket: %w", err)
	}

	peerUDPAddr, err := net.ResolveUDPAddr("udp4", peerAddr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("resolve peer addr: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	l := &directP2PListener{
		conn:     conn,
		peerAddr: peerUDPAddr,
		ctx:      ctx,
		cancel:   cancel,
	}

	// Start the KCP listener on the punch socket.
	kcpL, err := kcp.ServeConn(nil, 0, 0, conn)
	if err != nil {
		conn.Close()
		cancel()
		return nil, fmt.Errorf("kcp listener: %w", err)
	}
	l.kcp = kcpL

	// Send NAT-kick bursts in background, every 2s for 10s, to give
	// both peers time to start simultaneously.
	go kickFor(l.ctx, l.conn, l.peerAddr, kickDuration)

	return l, nil
}

// Accept blocks until a peer punches the punch socket and completes a KCP
// handshake, then returns the resulting kamune.Conn.
func (l *directP2PListener) Accept() (kamune.Conn, error) {
	sess, err := l.kcp.AcceptKCP()
	if err != nil {
		return nil, err
	}
	return kamune.NewConn(sess), nil
}

// Close releases the punch socket and stops the KCP listener. Safe to
// call multiple times.
func (l *directP2PListener) Close() error {
	l.closeOnce.Do(func() {
		l.cancel()
		if l.kcp != nil {
			_ = l.kcp.Close()
		}
		if l.conn != nil {
			l.closeErr = l.conn.Close()
		}
	})
	return l.closeErr
}

// Addr returns the punch socket's local address.
func (l *directP2PListener) Addr() *net.UDPAddr {
	if l.conn == nil {
		return nil
	}
	if addr, ok := l.conn.LocalAddr().(*net.UDPAddr); ok {
		return addr
	}
	return nil
}

// directP2PDial creates a UDP socket, sends a NAT-kick burst to peerAddr,
// and returns a KCP client session wrapped as a kamune.Conn. The caller
// should use this with kamune.DialWithFunc to bypass the standard dial.
func directP2PDial(
	ctx context.Context, peerAddr string,
) (kamune.Conn, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("bind punch socket: %w", err)
	}

	peerUDPAddr, err := net.ResolveUDPAddr("udp4", peerAddr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("resolve peer addr: %w", err)
	}

	// Send NAT-kick burst. Use a short timeout — the peer should be
	// starting its listener simultaneously.
	kickCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	sendNATKick(kickCtx, conn, peerUDPAddr)
	if err := ctx.Err(); err != nil {
		conn.Close()
		return nil, err
	}

	// Create a KCP client session on the punch socket. The first Write
	// triggers the KCP SYN; the peer's kcp.ServeConn accepts it.
	var convid uint32
	binary.Read(rand.Reader, binary.LittleEndian, &convid)
	sess, err := kcp.NewConn4(convid, peerUDPAddr, nil, 0, 0, true, conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("kcp session: %w", err)
	}
	return kamune.NewConn(sess), nil
}
