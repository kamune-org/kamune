package kamune

import "bytes"

// PeerConstraint is a connection that only accepts listed peer keys.
// A handshake calls AllowPeer after the peer has authenticated.
type PeerConstraint interface {
	AllowPeer(pkix []byte) bool
}

type peerExpect struct {
	Conn
	keys [][]byte
}

// ExpectPeer wraps c so AllowPeer accepts only the given PKIX keys.
func ExpectPeer(c Conn, keys ...[]byte) Conn {
	cloned := make([][]byte, len(keys))
	for i, k := range keys {
		cloned[i] = bytes.Clone(k)
	}
	return peerExpect{Conn: c, keys: cloned}
}

func (p peerExpect) AllowPeer(pkix []byte) bool {
	for _, k := range p.keys {
		if bytes.Equal(k, pkix) {
			return true
		}
	}
	return false
}
