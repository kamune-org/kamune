package main

import (
	"bytes"
	"net"
	"sync"

	"github.com/kamune-org/kamune"
)

// peerGate is implemented by the AcceptedMeta of a conn that came in
// through a listener opened for particular peers, such as a relay or
// broker token derived from one peer's key. Such a token is a hash of
// both public keys, so anyone who knows the keys can use it; the server
// handler drops a session whose peer the gate does not admit.
type peerGate interface {
	admitsPeer(key []byte) bool
}

// peerKeySet is the set of peer keys a listener was opened for. Until a
// key is added it admits every peer, as does a set opened to anyone.
type peerKeySet struct {
	mu     sync.RWMutex
	pinned bool
	open   bool
	keys   [][]byte
}

// allow adds key to the set. A nil key opens the set to every peer, for a
// token that is not tied to a peer.
func (s *peerKeySet) allow(key []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pinned = true
	if key == nil {
		s.open = true
		return
	}
	s.keys = append(s.keys, bytes.Clone(key))
}

func (s *peerKeySet) admitsPeer(key []byte) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.pinned || s.open {
		return true
	}
	for _, k := range s.keys {
		if bytes.Equal(k, key) {
			return true
		}
	}
	return false
}

// gatedConn carries a listener's peer gate through the handshake.
type gatedConn struct {
	kamune.Conn
	gate peerGate
}

func (c *gatedConn) AcceptedMeta() any { return c.gate }

// RemoteAddr reports the wrapped conn's address, so the server still
// limits pending handshakes per source.
func (c *gatedConn) RemoteAddr() net.Addr {
	if ra, ok := c.Conn.(interface{ RemoteAddr() net.Addr }); ok {
		return ra.RemoteAddr()
	}
	return nil
}

// admittedBy reports whether the listener a session came in through
// admits key; sessions from listeners without a gate are admitted.
func admittedBy(meta any, key []byte) bool {
	g, ok := meta.(peerGate)
	return !ok || g.admitsPeer(key)
}
