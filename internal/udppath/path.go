package udppath

import (
	"crypto/cipher"
	"net"
	"net/netip"
)

// role is the end of the path handshake the local side ran.
type role uint8

const (
	roleClient role = iota + 1
	roleServer
)

// Path is one dialer-to-listener association, bound to one peer address and
// port by a completed path handshake.
type Path struct {
	send     cipher.AEAD
	recv     cipher.AEAD
	raddrUDP *net.UDPAddr
	raddr    netip.AddrPort
	cid      uint32
	sid      uint32
}

// newPath returns the path with client id cid and server id sid to raddr.
// r picks which of the keys seals what the local side sends.
func newPath(
	r role, raddr netip.AddrPort, cid, sid uint32, keys pathKeys,
) *Path {
	raddr = unmap(raddr)
	p := &Path{
		raddr:    raddr,
		raddrUDP: net.UDPAddrFromAddrPort(raddr),
		cid:      cid,
		sid:      sid,
		send:     keys.c2s,
		recv:     keys.s2c,
	}
	if r == roleServer {
		p.send, p.recv = keys.s2c, keys.c2s
	}
	return p
}

// Conv returns the client id, which is also the KCP conv of the path.
func (p *Path) Conv() uint32 { return p.cid }

// RemoteAddr returns the peer's address and port, without an IPv4-in-IPv6
// mapping.
func (p *Path) RemoteAddr() netip.AddrPort { return p.raddr }

// RemoteUDPAddr returns the peer's address as a [net.UDPAddr]. It is the same
// value on every call.
func (p *Path) RemoteUDPAddr() *net.UDPAddr { return p.raddrUDP }

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
