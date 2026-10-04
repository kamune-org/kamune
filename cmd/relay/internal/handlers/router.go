package handlers

import (
	"net"
	"net/http"
	"strings"
)

// xForwardedFor is the canonical form of the one list-valued client
// address header clientIP understands.
const xForwardedFor = "X-Forwarded-For"

func extractIP(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		return host
	}
	return s
}

func validateIP(s string) string {
	raw := extractIP(s)
	if raw == "" {
		return ""
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		return ""
	}
	return ip.String()
}

// clientIP returns the address a request is keyed and logged by. Only when
// the TCP peer is in trustedProxies does it read a header, and then only
// header (canonical form). A proxy sets one client address header and
// passes the others through from the client, so reading any other one
// would let the client choose its own address. It falls back to the TCP
// peer when the header holds no usable address.
func clientIP(
	r *http.Request, trustedProxies []*net.IPNet, header string,
) string {
	remoteIP := validateIP(r.RemoteAddr)
	if remoteIP == "" {
		remoteIP = extractIP(r.RemoteAddr)
	}
	if !ipInRanges(net.ParseIP(remoteIP), trustedProxies) {
		return remoteIP
	}

	var ip string
	if header == xForwardedFor {
		ip = forwardedClientIP(r.Header.Values(header), trustedProxies)
	} else {
		ip = singleHeaderIP(r.Header.Values(header))
	}
	if ip == "" {
		return remoteIP
	}
	return ip
}

// forwardedClientIP returns the right-most X-Forwarded-For entry, across
// all header lines, that is not a trusted proxy. Each proxy appends the
// address it got the request from, so everything left of that entry was
// written by the client. An entry that does not parse ends the search, as
// a trusted proxy did not write it.
func forwardedClientIP(values []string, trustedProxies []*net.IPNet) string {
	parts := strings.Split(strings.Join(values, ","), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := validateIP(parts[i])
		if ip == "" {
			return ""
		}
		if !ipInRanges(net.ParseIP(ip), trustedProxies) {
			return ip
		}
	}
	return ""
}

// singleHeaderIP returns the address in a header that a proxy sets to one
// address, such as X-Real-IP or CF-Connecting-IP. Several lines or a list
// mean the proxy did not replace what the client sent, so none is used.
func singleHeaderIP(values []string) string {
	if len(values) != 1 || strings.Contains(values[0], ",") {
		return ""
	}
	return validateIP(values[0])
}

func ipInRanges(ip net.IP, ranges []*net.IPNet) bool {
	if ip == nil {
		return false
	}
	for _, block := range ranges {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}
