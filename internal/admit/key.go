package admit

import (
	"net"
	"net/netip"
)

const (
	// ipv6SourceBits is the prefix length by which the per-source limit groups
	// IPv6 addresses, since one host commonly holds a whole /64.
	ipv6SourceBits = 64

	// ipv4NetworkBits and ipv6NetworkBits are the prefix lengths by which the
	// cap on waiting connections groups addresses into networks when it picks a
	// connection to drop. One site commonly holds an IPv6 /48, which is 65,536
	// /64s.
	ipv4NetworkBits = 24
	ipv6NetworkBits = 48
)

// SourceKey returns the key under which the per-source limit counts a
// connection from addr: its IP address, or for IPv6 the address's /64 prefix.
// An address that is not an IP address, with or without a port, is used as it
// is.
func SourceKey(addr net.Addr) string {
	ip, host, ok := hostIP(addr)
	switch {
	case !ok:
		return host
	case ip.Is4():
		return ip.String()
	default:
		return prefixKey(ip, ipv6SourceBits)
	}
}

// NetworkKey returns the key under which the cap on waiting connections groups
// a connection from addr when it picks one to drop: the /24 prefix of its IPv4
// address, or the /48 prefix of its IPv6 address. An address that is not an IP
// address, with or without a port, is used as it is.
func NetworkKey(addr net.Addr) string {
	ip, host, ok := hostIP(addr)
	switch {
	case !ok:
		return host
	case ip.Is4():
		return prefixKey(ip, ipv4NetworkBits)
	default:
		return prefixKey(ip, ipv6NetworkBits)
	}
}

// SourceKeyAddrPort returns the per-source key of ap. It removes an
// IPv4-in-IPv6 mapping, then uses the IPv4 host or the IPv6 /64.
func SourceKeyAddrPort(ap netip.AddrPort) string {
	ip := ap.Addr().Unmap()
	if ip.Is4() {
		return ip.String()
	}
	return prefixKey(ip, ipv6SourceBits)
}

// NetworkKeyAddrPort returns the network key of ap. It removes an
// IPv4-in-IPv6 mapping, then uses the IPv4 /24 or the IPv6 /48.
func NetworkKeyAddrPort(ap netip.AddrPort) string {
	ip := ap.Addr().Unmap()
	if ip.Is4() {
		return prefixKey(ip, ipv4NetworkBits)
	}
	return prefixKey(ip, ipv6NetworkBits)
}

// hostIP returns the host part of addr and, when it is an IP address, that
// address with any IPv4-in-IPv6 mapping removed and true.
func hostIP(addr net.Addr) (netip.Addr, string, bool) {
	host := addr.String()
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, host, false
	}
	return ip.Unmap(), host, true
}

// prefixKey returns the prefix of ip with the given length as a string.
func prefixKey(ip netip.Addr, bits int) string {
	prefix, err := ip.Prefix(bits)
	if err != nil {
		return ip.String()
	}
	return prefix.String()
}
