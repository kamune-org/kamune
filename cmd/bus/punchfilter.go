package main

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	// matchWindow is how long a p2p listener takes KCP packets from the
	// IP address of a peer the broker matched it with.
	matchWindow = time.Minute
	// maxMatchedPeers caps the matched peers a p2p listener expects at
	// once.
	maxMatchedPeers = 64
	// kickDuration is how long a listener keeps sending NAT kicks to a
	// peer, and kickInterval the wait between two bursts.
	kickDuration = 10 * time.Second
	kickInterval = 2 * time.Second
)

// punchFilter is the net.PacketConn that a P2P listener hands to kcp-go
// in place of its punch socket. kcp-go starts a session for any datagram
// of 24 bytes or more from an address it has no session with, so a
// broker NOTIFY, or a datagram from anyone who learns the port, would
// reach the kamune server as a new connection. punchFilter hands each
// packet from the broker to onBroker instead, and passes on only the
// packets of an expected peer: from the IP address of the direct P2P
// peer, from that of a peer the broker matched within matchWindow, or
// from the address of a session the listener accepted, until that
// session closes.
//
// Only the IP address of a direct or matched peer is checked, not its
// port: a NAT may send the peer's packets from a port other than the one
// the broker saw, and a direct P2P dialer sends from a port of its own.
//
// punchFilter lacks the methods of *net.UDPConn that kcp-go uses for
// batch reads, so kcp-go reads it through ReadFrom.
type punchFilter struct {
	conn *net.UDPConn
	// broker is the broker's address, and onBroker gets its packets.
	// Both are unset for a direct P2P listener.
	broker   netip.AddrPort
	onBroker func(pkt []byte)
	// direct is the IP address of the direct P2P peer, if any.
	direct netip.Addr

	mu      sync.Mutex
	matched map[netip.Addr]time.Time
	live    map[netip.AddrPort]int
	now     func() time.Time
}

func newPunchFilter(conn *net.UDPConn) *punchFilter {
	return &punchFilter{
		conn:    conn,
		matched: make(map[netip.Addr]time.Time),
		live:    make(map[netip.AddrPort]int),
		now:     time.Now,
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

// expect has the filter pass on packets from ip for matchWindow. It
// drops the peer expected the longest when maxMatchedPeers are.
func (f *punchFilter) expect(ip netip.Addr) {
	ip = ip.Unmap()
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	for a, until := range f.matched {
		if !now.Before(until) {
			delete(f.matched, a)
		}
	}
	if _, ok := f.matched[ip]; !ok && len(f.matched) >= maxMatchedPeers {
		var oldest netip.Addr
		var first time.Time
		for a, until := range f.matched {
			if !oldest.IsValid() || until.Before(first) {
				oldest, first = a, until
			}
		}
		delete(f.matched, oldest)
	}
	f.matched[ip] = now.Add(matchWindow)
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
	until, ok := f.matched[src.Addr()]
	return ok && f.now().Before(until)
}

// ReadFrom returns the next packet from an expected peer. It hands the
// packets from the broker to onBroker and drops every other packet.
func (f *punchFilter) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, src, err := f.conn.ReadFromUDPAddrPort(p)
		if err != nil {
			return n, nil, err
		}
		src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
		if f.broker.IsValid() && src == f.broker {
			if f.onBroker != nil {
				f.onBroker(p[:n])
			}
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

// kickFor sends bursts of NAT kicks from conn to addr, one at once and
// then one every kickInterval, for d or until ctx ends. A kick opens the
// mapping for addr in the local NAT, so that the peer's packets get in.
func kickFor(
	ctx context.Context, conn *net.UDPConn, addr *net.UDPAddr,
	d time.Duration,
) {
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	for {
		sendNATKick(ctx, conn, addr)
		t := time.NewTimer(kickInterval)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}
