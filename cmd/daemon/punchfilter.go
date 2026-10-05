package main

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/xtaci/kcp-go/v5"
)

const (
	// matchWindow is how long a p2p listener takes KCP packets from the
	// IP address of a peer that the broker matched it with. Packets from
	// the peer do not renew it: a session that the peer opened in time
	// is held for as long as it lives instead; see punchFilter.hold.
	matchWindow = time.Minute
	// maxMatchedPeers caps the matched peers that a p2p listener expects
	// at once.
	maxMatchedPeers = 64
	// divertQuiet is how long a punchFilter drops the packets of an
	// address after the dial that it diverted them to ended, so that the
	// peer's last packets for that dial do not open a session with the
	// listener.
	divertQuiet = 10 * time.Second
	// divertBacklog is how many packets a diverted dial may have waiting
	// before more are dropped.
	divertBacklog = 256
)

// errDiverted is returned by punchFilter.divertFrom for an address that
// the filter already hands to a dial or to a session the listener
// accepted.
var errDiverted = errors.New(
	"the punch socket already has a session with that address",
)

// matchedPeer is a peer that a punchFilter expects: until when, and the
// wire form of the token that the broker matched it on, in hex.
type matchedPeer struct {
	until time.Time
	token string
}

// punchFilter is the net.PacketConn that a p2p or direct p2p listener
// hands to kcp-go in place of its punch socket. kcp-go starts a session
// for any datagram of 24 bytes or more from an address that it has no
// session with, so a broker NOTIFY, or a datagram from anyone who learns
// the port, would reach the kamune server as a new connection.
// punchFilter hands each packet from the broker to onBroker instead, and
// passes on only the packets of an expected peer: from the IP address of
// the direct p2p peer, from that of a peer the broker matched within
// matchWindow on a token the listener still registers, or from the
// address of a session the listener accepted, until that session
// closes. The packets of a session that the daemon dialed from the punch
// socket go to that session instead; see divertFrom.
//
// Only the IP address of a direct or matched peer is checked, not its
// port: a NAT may send the peer's packets from a port other than the one
// the broker saw, and a direct p2p dialer sends from a port of its own.
//
// punchFilter lacks the methods of *net.UDPConn that kcp-go uses for
// batch reads, so kcp-go reads it through ReadFrom.
type punchFilter struct {
	conn *net.UDPConn
	// broker is the broker's address, and onBroker gets its packets.
	// Both are unset for a direct p2p listener.
	broker   netip.AddrPort
	onBroker func(pkt []byte)
	// direct is the IP address of the direct p2p peer, if any.
	direct netip.Addr

	mu      sync.Mutex
	matched map[netip.Addr]matchedPeer
	live    map[netip.AddrPort]int
	// diverted holds the dials from the punch socket by the address of
	// their peer, and quiet the addresses of ended dials, until when
	// their packets are dropped.
	diverted map[netip.AddrPort]*divertConn
	quiet    map[netip.AddrPort]time.Time
	now      func() time.Time
}

func newPunchFilter(conn *net.UDPConn) *punchFilter {
	return &punchFilter{
		conn:     conn,
		matched:  make(map[netip.Addr]matchedPeer),
		live:     make(map[netip.AddrPort]int),
		diverted: make(map[netip.AddrPort]*divertConn),
		quiet:    make(map[netip.AddrPort]time.Time),
		now:      time.Now,
	}
}

// addrPortOf returns addr as a netip.AddrPort with an IPv4 address in its
// 4-byte form, or false when addr is not a UDP address.
func addrPortOf(addr net.Addr) (netip.AddrPort, bool) {
	ua, ok := addr.(*net.UDPAddr)
	if !ok || ua == nil {
		return netip.AddrPort{}, false
	}
	ap := ua.AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
}

// expect has the filter pass on packets from ip for matchWindow, for the
// broker's match on token, the wire form of a token in hex. It drops the
// peer expected the longest when maxMatchedPeers are.
func (f *punchFilter) expect(ip netip.Addr, token string) {
	ip = ip.Unmap()
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	for a, m := range f.matched {
		if !now.Before(m.until) {
			delete(f.matched, a)
		}
	}
	if _, ok := f.matched[ip]; !ok && len(f.matched) >= maxMatchedPeers {
		var oldest netip.Addr
		var first time.Time
		for a, m := range f.matched {
			if !oldest.IsValid() || m.until.Before(first) {
				oldest, first = a, m.until
			}
		}
		delete(f.matched, oldest)
	}
	f.matched[ip] = matchedPeer{until: now.Add(matchWindow), token: token}
}

// forget stops expecting the peers that the broker matched on token, the
// wire form of a token in hex, which the listener no longer registers.
// A session that such a peer opened already is still held.
func (f *punchFilter) forget(token string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for a, m := range f.matched {
		if m.token == token {
			delete(f.matched, a)
		}
	}
}

// hold has the filter pass on packets from addr, the address of a
// session the listener accepted, until release is called.
func (f *punchFilter) hold(addr net.Addr) (release func()) {
	ap, ok := addrPortOf(addr)
	if !ok {
		return func() {}
	}
	f.mu.Lock()
	f.live[ap]++
	f.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.live[ap] <= 1 {
				delete(f.live, ap)
			} else {
				f.live[ap]--
			}
		})
	}
}

// admits reports whether a packet from src is passed on to kcp-go.
func (f *punchFilter) admits(src netip.AddrPort) bool {
	if f.direct.IsValid() && src.Addr() == f.direct {
		return true
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.live[src] > 0 {
		return true
	}
	m, ok := f.matched[src.Addr()]
	return ok && f.now().Before(m.until)
}

// divertFrom has the filter hand the packets from addr to the
// net.PacketConn it returns, in place of the listener, until that is
// closed: a dial can then run a KCP session from the punch socket. It
// fails with errDiverted while a session the listener accepted, or
// another dial, has packets from addr.
func (f *punchFilter) divertFrom(addr netip.AddrPort) (*divertConn, error) {
	addr = netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.live[addr] > 0 || f.diverted[addr] != nil {
		return nil, errDiverted
	}
	delete(f.quiet, addr)
	c := &divertConn{
		f:    f,
		addr: addr,
		in:   make(chan []byte, divertBacklog),
		done: make(chan struct{}),
	}
	f.diverted[addr] = c
	return c, nil
}

// closeDiverted closes the conn of every dial that the filter diverts
// packets to, so that their sessions fail rather than wait for packets.
func (f *punchFilter) closeDiverted() {
	f.mu.Lock()
	conns := make([]*divertConn, 0, len(f.diverted))
	for _, c := range f.diverted {
		conns = append(conns, c)
	}
	f.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

// route hands pkt, a packet from src, to the dial that src is diverted
// to, and reports whether the packet is taken: by such a dial, or
// dropped because a dial with src ended a moment ago.
func (f *punchFilter) route(src netip.AddrPort, pkt []byte) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c := f.diverted[src]; c != nil {
		select {
		case c.in <- bytes.Clone(pkt):
		default:
		}
		return true
	}
	until, ok := f.quiet[src]
	if !ok {
		return false
	}
	if f.now().Before(until) {
		return true
	}
	delete(f.quiet, src)
	return false
}

// ReadFrom returns the next packet from an expected peer. It hands the
// packets from the broker to onBroker and those of a diverted dial to
// the dial, and drops every other packet.
func (f *punchFilter) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, src, err := f.conn.ReadFromUDPAddrPort(p)
		if err != nil {
			// kcp-go stops reading, and the dials get no more
			// packets either.
			f.closeDiverted()
			return n, nil, err
		}
		src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
		if f.broker.IsValid() && src == f.broker {
			if f.onBroker != nil {
				f.onBroker(p[:n])
			}
			continue
		}
		if f.route(src, p[:n]) {
			continue
		}
		if f.admits(src) {
			return n, net.UDPAddrFromAddrPort(src), nil
		}
	}
}

func (f *punchFilter) WriteTo(p []byte, addr net.Addr) (int, error) {
	return f.conn.WriteTo(p, addr)
}

func (f *punchFilter) Close() error        { return f.conn.Close() }
func (f *punchFilter) LocalAddr() net.Addr { return f.conn.LocalAddr() }

func (f *punchFilter) SetDeadline(t time.Time) error {
	return f.conn.SetDeadline(t)
}

func (f *punchFilter) SetReadDeadline(t time.Time) error {
	return f.conn.SetReadDeadline(t)
}

func (f *punchFilter) SetWriteDeadline(t time.Time) error {
	return f.conn.SetWriteDeadline(t)
}

// heldSession is a KCP session that a punchFilter passes packets on for
// until it is closed; see punchFilter.hold.
type heldSession struct {
	*kcp.UDPSession
	release func()
}

func (s *heldSession) Close() error {
	s.release()
	return s.UDPSession.Close()
}

// acceptHeld accepts the next KCP session from l and has f pass on its
// packets until it is closed.
func acceptHeld(l *kcp.Listener, f *punchFilter) (*heldSession, error) {
	sess, err := l.AcceptKCP()
	if err != nil {
		return nil, err
	}
	return &heldSession{
		UDPSession: sess, release: f.hold(sess.RemoteAddr()),
	}, nil
}

// divertConn is the net.PacketConn of a KCP session that the daemon
// dialed from a p2p listener's punch socket: it reads the packets that
// the listener's punchFilter diverts from the peer's address, and writes
// to the punch socket.
type divertConn struct {
	f         *punchFilter
	addr      netip.AddrPort
	in        chan []byte
	done      chan struct{}
	closeOnce sync.Once
}

func (c *divertConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case pkt := <-c.in:
		return copy(p, pkt), net.UDPAddrFromAddrPort(c.addr), nil
	case <-c.done:
		return 0, nil, net.ErrClosed
	}
}

func (c *divertConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}
	return c.f.conn.WriteTo(p, addr)
}

// Close ends the diversion: the filter drops the packets from the peer's
// address for divertQuiet, and then lets them reach the listener again.
// It leaves the punch socket open.
func (c *divertConn) Close() error {
	c.closeOnce.Do(func() {
		c.f.mu.Lock()
		if c.f.diverted[c.addr] == c {
			delete(c.f.diverted, c.addr)
			c.f.quiet[c.addr] = c.f.now().Add(divertQuiet)
		}
		c.f.mu.Unlock()
		close(c.done)
	})
	return nil
}

func (c *divertConn) LocalAddr() net.Addr { return c.f.conn.LocalAddr() }

// SetDeadline, SetReadDeadline and SetWriteDeadline do nothing: kcp-go
// keeps the deadlines of a session itself.
func (c *divertConn) SetDeadline(time.Time) error      { return nil }
func (c *divertConn) SetReadDeadline(time.Time) error  { return nil }
func (c *divertConn) SetWriteDeadline(time.Time) error { return nil }

// divertedSession is a KCP session over a divertConn, which it closes
// with it.
type divertedSession struct {
	*kcp.UDPSession
	conn *divertConn
}

func (s *divertedSession) Close() error {
	err := s.UDPSession.Close()
	_ = s.conn.Close()
	return err
}
