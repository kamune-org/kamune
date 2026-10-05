package main

import (
	"net"
	"net/netip"
	"time"
)

// punchFilter is the net.PacketConn that a direct p2p listener hands to
// kcp-go in place of its punch socket. kcp-go starts a session for any
// datagram of 24 bytes or more from an address that it has no session
// with, so a datagram from anyone who learns the port would reach the
// kamune server as a new connection. punchFilter passes on only the
// packets from the IP address of the direct p2p peer.
//
// Only the IP address of the direct peer is checked, not its port: a
// direct p2p dialer sends from a port of its own.
//
// punchFilter lacks the methods of *net.UDPConn that kcp-go uses for
// batch reads, so kcp-go reads it through ReadFrom.
type punchFilter struct {
	conn *net.UDPConn
	// direct is the IP address of the direct p2p peer, if any.
	direct netip.Addr
}

func newPunchFilter(conn *net.UDPConn) *punchFilter {
	return &punchFilter{conn: conn}
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

// admits reports whether a packet from src is passed on to kcp-go.
func (f *punchFilter) admits(src netip.AddrPort) bool {
	return f.direct.IsValid() && src.Addr() == f.direct
}

// ReadFrom returns the next packet from an expected peer, and drops
// every other packet.
func (f *punchFilter) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, src, err := f.conn.ReadFromUDPAddrPort(p)
		if err != nil {
			return n, nil, err
		}
		src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
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
