package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/kamune-org/kamune"
)

// directP2PDialTimeout bounds one direct P2P dial. It covers the
// listener's 10 s kick window (natKickLoop).
const directP2PDialTimeout = 10 * time.Second

// directP2PListener is a kamune.Listener that accepts a session from a
// peer whose address is known up front. The UDP path layer drops every
// datagram from an IP other than the peer's, so only that peer can open
// a session. The port is not checked: the dialer binds a port of its
// own.
type directP2PListener struct {
	ln        kamune.Listener
	ctx       context.Context
	closeErr  error
	conn      *net.UDPConn
	peerAddr  *net.UDPAddr
	cancel    context.CancelFunc
	closeOnce sync.Once
}

func newDirectP2PListener(
	listenAddr, peerAddr string,
) (*directP2PListener, error) {
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
		_ = conn.Close()
		return nil, fmt.Errorf("resolve peer addr: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var peerIP netip.Addr
	if ap, ok := addrPortOf(peerUDPAddr); ok {
		peerIP = ap.Addr()
	}
	isPeerIP := func(from netip.AddrPort) bool {
		return peerIP.IsValid() && from.Addr().Unmap() == peerIP
	}
	ln, err := kamune.ListenUDP(
		conn, kamune.UDPWithSourceFilter(isPeerIP),
	)
	if err != nil {
		_ = conn.Close()
		cancel()
		return nil, fmt.Errorf("listen udp: %w", err)
	}

	l := &directP2PListener{
		ln:       ln,
		ctx:      ctx,
		conn:     conn,
		peerAddr: peerUDPAddr,
		cancel:   cancel,
	}
	go l.natKickLoop()
	return l, nil
}

func (l *directP2PListener) natKickLoop() {
	timeout := time.After(10 * time.Second)
	for {
		_, _ = sendNATKick(l.ctx, l.conn, l.peerAddr)
		select {
		case <-l.ctx.Done():
			return
		case <-timeout:
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func (l *directP2PListener) Accept() (kamune.Conn, error) {
	return l.ln.Accept()
}

// Close stops the NAT kicks and closes the path listener. An accepted
// session keeps the socket until that session ends. Close is safe to
// call more than once.
func (l *directP2PListener) Close() error {
	l.closeOnce.Do(func() {
		l.cancel()
		if l.ln != nil {
			l.closeErr = l.ln.Close()
		}
	})
	return l.closeErr
}

func (l *directP2PListener) Addr() *net.UDPAddr {
	if l.conn == nil {
		return nil
	}
	if addr, ok := l.conn.LocalAddr().(*net.UDPAddr); ok {
		return addr
	}
	return nil
}

// directP2PDial binds a UDP socket and runs the path handshake to
// peerAddr, whose HELLOs open the local NAT mapping. Every error wraps
// ErrHolePunchFailed, and the socket is closed on error.
func directP2PDial(
	ctx context.Context, peerAddr string,
) (kamune.Conn, error) {
	conn, err := net.ListenUDP(
		"udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0},
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrHolePunchFailed, err)
	}
	peerUDPAddr, err := net.ResolveUDPAddr("udp4", peerAddr)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: %w", ErrHolePunchFailed, err)
	}
	ap := peerUDPAddr.AddrPort()
	ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	dialCtx, cancel := context.WithTimeout(ctx, directP2PDialTimeout)
	defer cancel()
	kc, err := kamune.DialUDP(dialCtx, conn, ap)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: %w", ErrHolePunchFailed, err)
	}
	return kc, nil
}
