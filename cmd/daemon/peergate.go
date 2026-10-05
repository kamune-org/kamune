package main

import (
	"net"

	"github.com/kamune-org/kamune"
)

// peerGate is implemented by the AcceptedMeta of a conn that came in
// through a listener opened for particular peers: a relay listener
// registered with a static token, or a p2p listener whose tokens are
// static. A static token is a hash of both peers' public keys, so anyone
// who knows the keys can use it, and the relay or the broker picks who
// does. serverHandler drops a session whose peer the gate does not
// admit; see admittedBy.
type peerGate interface {
	admitsPeer(key []byte) bool
}

// gatedConn carries the peer gate of the listener it came in through.
type gatedConn struct {
	kamune.Conn
	gate peerGate
}

func (c *gatedConn) AcceptedMeta() any { return c.gate }

// RemoteAddr reports the wrapped conn's address, so that the server
// still limits pending handshakes per source.
func (c *gatedConn) RemoteAddr() net.Addr {
	if ra, ok := c.Conn.(interface{ RemoteAddr() net.Addr }); ok {
		return ra.RemoteAddr()
	}
	return nil
}

// admittedBy reports whether meta, the AcceptedMeta of a session's
// conn, admits the peer whose key is key. A conn from a listener that
// has no gate admits every peer.
func admittedBy(meta any, key []byte) bool {
	g, ok := meta.(peerGate)
	return !ok || g.admitsPeer(key)
}
