package udppath

import (
	"crypto/cipher"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// role is the end of the path handshake the local side ran.
type role uint8

const (
	roleClient role = iota + 1
	roleServer
)

// closeReason says why a path closed. It decides whether CLOSE is sent.
type closeReason uint8

const (
	// reasonLocal is Close, or a send counter that ran out.
	reasonLocal closeReason = iota + 1
	// reasonPeer is a valid CLOSE from the peer, which needs no answer.
	reasonPeer
	// reasonSocket is the socket closed under the reader: nothing can be
	// sent.
	reasonSocket
)

var (
	inPool   = sync.Pool{New: func() any { return new([KCPMTU]byte) }}
	sealPool = sync.Pool{New: func() any { return new([MaxDatagram]byte) }}
)

// inbound is one opened KCP packet waiting for ReadFrom.
type inbound struct {
	buf *[KCPMTU]byte
	n   int
}

// Path is one dialer-to-listener association, bound to one peer address and
// port by a completed path handshake. It is the [net.PacketConn] of one
// kcp-go session: ReadFrom returns the opened KCP packets of the path and
// WriteTo seals KCP packets to the peer.
type Path struct {
	send     cipher.AEAD
	recv     cipher.AEAD
	pc       net.PacketConn
	raddrUDP *net.UDPAddr
	stats    *counters
	// rd is the reader of a client path's socket, which the path owns.
	rd      *reader
	in      chan inbound
	started chan struct{}
	done    chan struct{}
	raddr   netip.AddrPort
	// win belongs to the reader goroutine.
	win         window
	sendCtr     atomic.Uint64
	startOnce   sync.Once
	closeOnce   sync.Once
	releaseOnce sync.Once
	cid         uint32
	sid         uint32
	// sendID is the receiver's id in what the path sends: sid from the
	// client, cid from the server.
	sendID uint32
}

// newPath returns the path with client id cid and server id sid to raddr on
// pc. r picks which of the keys seals what the local side sends.
func newPath(
	r role,
	pc net.PacketConn,
	stats *counters,
	raddr netip.AddrPort,
	cid, sid uint32,
	keys pathKeys,
) *Path {
	raddr = unmap(raddr)
	p := &Path{
		pc:       pc,
		stats:    stats,
		raddr:    raddr,
		raddrUDP: net.UDPAddrFromAddrPort(raddr),
		cid:      cid,
		sid:      sid,
		send:     keys.c2s,
		recv:     keys.s2c,
		sendID:   sid,
		in:       make(chan inbound, PathInbound),
		started:  make(chan struct{}),
		done:     make(chan struct{}),
	}
	if r == roleServer {
		p.send, p.recv = keys.s2c, keys.c2s
		p.sendID = cid
	}
	return p
}

// Conv returns the client id, which is also the KCP conv of the path.
func (p *Path) Conv() uint32 { return p.cid }

// RemoteAddr returns the peer's address and port, without an IPv4-in-IPv6
// mapping.
func (p *Path) RemoteAddr() netip.AddrPort { return p.raddr }

// RemoteUDPAddr returns the peer's address as a [net.UDPAddr]. It is the same
// value on every call, and the address ReadFrom returns.
func (p *Path) RemoteUDPAddr() *net.UDPAddr { return p.raddrUDP }

// LocalAddr returns the address of the path's socket.
func (p *Path) LocalAddr() net.Addr { return p.pc.LocalAddr() }

// Stats returns the counters of the path's socket.
func (p *Path) Stats() Stats { return p.stats.snapshot() }

// Start lets ReadFrom return packets. The caller sets the KCP MTU first, so
// that kcp-go never reads or writes at its default MTU.
func (p *Path) Start() {
	p.startOnce.Do(func() { close(p.started) })
}

// SetDeadline does nothing. kcp-go keeps its own deadlines.
func (p *Path) SetDeadline(time.Time) error { return nil }

// SetReadDeadline does nothing.
func (p *Path) SetReadDeadline(time.Time) error { return nil }

// SetWriteDeadline does nothing.
func (p *Path) SetWriteDeadline(time.Time) error { return nil }

// ReadFrom waits for Start, then returns the next KCP packet of the path and
// the peer's address. Once the path is closed it returns the packets still
// queued, then [ErrPathClosed].
func (p *Path) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case <-p.started:
	case <-p.done:
	}
	select {
	case in := <-p.in:
		return p.deliver(b, in)
	case <-p.done:
		select {
		case in := <-p.in:
			return p.deliver(b, in)
		default:
			return 0, nil, ErrPathClosed
		}
	}
}

func (p *Path) deliver(b []byte, in inbound) (int, net.Addr, error) {
	n := copy(b, in.buf[:in.n])
	inPool.Put(in.buf)
	return n, p.raddrUDP, nil
}

// WriteTo seals the KCP packet b, of 1 to [KCPMTU] bytes, and sends it to
// the peer whatever addr is. A write error from the socket is returned as
// it is.
func (p *Path) WriteTo(b []byte, _ net.Addr) (int, error) {
	if len(b) < 1 || len(b) > KCPMTU {
		return 0, errPacketSize
	}
	select {
	case <-p.done:
		return 0, ErrPathClosed
	default:
	}
	ctr := p.sendCtr.Add(1)
	if ctr >= maxCounter {
		p.close(reasonLocal)
		return 0, ErrPathClosed
	}
	buf := sealPool.Get().(*[MaxDatagram]byte)
	defer sealPool.Put(buf)
	pkt := sealPacket(buf[:0], p.send, typeData, p.sendID, ctr, b)
	if _, err := p.pc.WriteTo(pkt, p.raddrUDP); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Close closes the path and sends CLOSE to the peer. A client path also
// closes its socket. Close is safe to call more than once.
func (p *Path) Close() error {
	p.close(reasonLocal)
	if p.rd != nil {
		p.releaseOnce.Do(func() {
			p.rd.halt()
			_ = p.pc.Close()
		})
	}
	return nil
}

// close ends the path once: ReadFrom drains and then fails, WriteTo fails,
// and the peer gets CLOSE twice unless it closed the path or the socket is
// gone.
func (p *Path) close(reason closeReason) {
	p.closeOnce.Do(func() {
		close(p.done)
		if reason == reasonLocal {
			p.sendClose()
			p.sendClose()
		}
	})
}

func (p *Path) sendClose() {
	ctr := p.sendCtr.Add(1)
	if ctr >= maxCounter {
		return
	}
	var buf [CloseSize]byte
	pkt := sealPacket(buf[:0], p.send, typeClose, p.sendID, ctr, nil)
	if _, err := p.pc.WriteTo(pkt, p.raddrUDP); err == nil {
		p.stats.CloseSent.Add(1)
	}
}

// input takes a DATA or CLOSE for this path from its address. It runs on
// the reader goroutine: it checks the counter against the window, opens
// the packet, and only then records the counter.
func (p *Path) input(m sealedMsg, pkt []byte) {
	if !p.win.check(m.ctr) {
		p.stats.Replay.Add(1)
		return
	}
	if m.typ == typeClose {
		if _, err := openPacket(nil, p.recv, m.ctr, pkt); err != nil {
			p.stats.BadTag.Add(1)
			return
		}
		p.win.update(m.ctr)
		p.stats.CloseReceived.Add(1)
		p.close(reasonPeer)
		return
	}
	buf := inPool.Get().(*[KCPMTU]byte)
	plain, err := openPacket(buf[:], p.recv, m.ctr, pkt)
	if err != nil {
		inPool.Put(buf)
		p.stats.BadTag.Add(1)
		return
	}
	p.win.update(m.ctr)
	select {
	case <-p.done:
		inPool.Put(buf)
		return
	default:
	}
	select {
	case p.in <- inbound{buf: buf, n: len(plain)}:
	default:
		inPool.Put(buf)
		p.stats.InboundDropped.Add(1)
	}
}

// unmap removes an IPv4-in-IPv6 mapping from ap.
func unmap(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// udpSource returns the unmapped source of a datagram read from a socket.
func udpSource(from net.Addr) (netip.AddrPort, bool) {
	ua, ok := from.(*net.UDPAddr)
	if !ok || ua == nil {
		return netip.AddrPort{}, false
	}
	ap := unmap(ua.AddrPort())
	return ap, ap.IsValid()
}
