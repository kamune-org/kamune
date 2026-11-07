package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kamune-org/kamune"
)

// directP2PDialTimeout bounds a direct P2P dial. It covers the listener's
// 10 s kick window (kickDuration).
const directP2PDialTimeout = 10 * time.Second

// directP2PListener accepts a peer whose address is known upfront. It
// sends NAT kicks to that address to open the local NAT mapping, then
// waits for the peer's UDP path handshake. The path layer admits only
// the peer's IP, on any port, because the dialer binds port 0. Used for
// UDP hole punching without a broker.
type directP2PListener struct {
	ln        kamune.Listener
	ctx       context.Context
	closeErr  error
	conn      *net.UDPConn
	peerAddr  *net.UDPAddr
	cancel    context.CancelFunc
	closeOnce sync.Once
}

// newDirectP2PListener binds listenAddr and accepts a UDP path from
// peerAddr. Both peers must be online together. NAT kicks go to peerAddr
// for kickDuration. A path is admitted only when its source IP, with any
// IPv4-mapped form removed, equals the peer's.
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
	peer, ok := addrPortOf(peerUDPAddr)
	if !ok || !peer.Addr().IsValid() {
		_ = conn.Close()
		return nil, fmt.Errorf("peer addr: not a UDP address")
	}

	ctx, cancel := context.WithCancel(context.Background())
	peerIP := peer.Addr()
	ln, err := kamune.ListenUDP(conn, kamune.UDPWithSourceFilter(
		func(from netip.AddrPort) bool {
			return from.Addr().Unmap() == peerIP
		},
	))
	if err != nil {
		_ = conn.Close()
		cancel()
		return nil, fmt.Errorf("udp path listener: %w", err)
	}

	l := &directP2PListener{
		conn:     conn,
		ln:       ln,
		peerAddr: peerUDPAddr,
		ctx:      ctx,
		cancel:   cancel,
	}
	// NAT kicks keep the mapping open while the peer starts. The path
	// listener owns reads and the close of conn.
	go kickFor(l.ctx, l.conn, l.peerAddr, kickDuration)
	return l, nil
}

// Accept returns the next conn from the path listener.
func (l *directP2PListener) Accept() (kamune.Conn, error) {
	return l.ln.Accept()
}

// Close stops the NAT kicks and closes the path listener. The listener
// owns the socket and closes it with the last accepted path, so a live
// session keeps working. conn is not closed here: the listener closes
// it, and closing it again would end that session. Safe to call twice.
func (l *directP2PListener) Close() error {
	l.closeOnce.Do(func() {
		l.cancel()
		if l.ln != nil {
			l.closeErr = l.ln.Close()
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

// directP2PDial binds a UDP socket and runs the path handshake to
// peerAddr. The path HELLOs open the NAT mapping. The caller passes the
// conn to kamune.DialWithFunc. On error the socket is closed.
func directP2PDial(
	ctx context.Context, peerAddr string,
) (kamune.Conn, error) {
	conn, err := net.ListenUDP(
		"udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0},
	)
	if err != nil {
		return nil, fmt.Errorf("bind punch socket: %w", err)
	}

	peerUDPAddr, err := net.ResolveUDPAddr("udp4", peerAddr)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("resolve peer addr: %w", err)
	}
	peer, ok := addrPortOf(peerUDPAddr)
	if !ok || !peer.Addr().IsValid() {
		_ = conn.Close()
		return nil, fmt.Errorf("peer addr: not a UDP address")
	}

	dialCtx, cancel := context.WithTimeout(ctx, directP2PDialTimeout)
	defer cancel()
	sess, err := kamune.DialUDP(dialCtx, conn, peer)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("udp path handshake: %w", err)
	}
	return sess, nil
}

// punchSession is the connection of a dial over a punched UDP socket. It
// records whether anything has come from the peer, which tells a punch
// that let nothing through from a handshake that failed after the punch
// worked; see dialErrorCode. The NAT kicks that the peer sends are too
// short for KCP, which drops them, so they do not count.
type punchSession struct {
	net.Conn
	answered atomic.Bool
}

func (c *punchSession) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.answered.Store(true)
	}
	return n, err
}
