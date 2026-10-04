package handlers

import "net"

// Listener wraps ln, the listener of a ws or wss server, so that each
// connection from a peer outside trusted_proxies spends one unit of the
// peer's connection quota as it is accepted, before the server does any
// TLS or HTTP work for it. A peer over quota is closed at once. Without
// this, a wss client could make the relay sign a TLS handshake for every
// connection it opens, however far over quota it is, by never sending a
// request. A trusted proxy's connections are not charged, as its address
// is shared by its clients; WebSocketHandler limits their requests by
// client address instead.
func (h *Handler) Listener(ln net.Listener) net.Listener {
	if h.connLimiter == nil {
		return ln
	}
	return &limitListener{Listener: ln, h: h}
}

type limitListener struct {
	net.Listener
	h *Handler
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.h.allowConn(conn.RemoteAddr()) {
			return conn, nil
		}
		_ = conn.Close()
	}
}

// allowConn charges a new connection from addr to its peer's connection
// quota, unless the peer is a trusted proxy.
func (h *Handler) allowConn(addr net.Addr) bool {
	ip := extractIP(addr.String())
	if ipInRanges(net.ParseIP(ip), h.trustedProxies) {
		return true
	}
	if h.connLimiter.Allow(rateLimitKey(ip)) {
		return true
	}
	logRateLimited(ip)
	return false
}
