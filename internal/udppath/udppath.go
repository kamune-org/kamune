// Package udppath is the UDP path layer of RFC008. It sits between a UDP
// socket and kcp-go and runs a two-round-trip path handshake per peer: HELLO
// and COOKIE prove that the dialer receives packets at its source address,
// and INIT and ACCEPT agree on per-path keys with an ephemeral X25519
// exchange. Every later packet of the path is sealed with those keys.
//
// The path keys are classical X25519 only. They protect the integrity,
// replay resistance and availability of KCP packets and hide KCP headers
// from passive observers. They carry no confidentiality claim: every kamune
// frame is protected end to end by the kamune handshake, and no layer may
// rely on the path keys for confidentiality or identity hiding.
package udppath

import (
	"errors"
	"fmt"
	"net"
	"time"
)

const (
	// Version is the path layer wire version.
	Version = 0x01

	// HelloSize, InitSize, CookieSize and AcceptSize are the exact sizes of
	// the handshake packets. HELLO and INIT are padded so that every reply
	// to an unverified source is smaller than the request.
	HelloSize  = 1200
	InitSize   = 1200
	CookieSize = 28
	AcceptSize = 60

	// CookieLifetime is how long a COOKIE stays valid at the server.
	CookieLifetime = 10 * time.Second

	// MaxHellos is how many HELLOs a dialer sends to an address that has not
	// answered with a COOKIE.
	MaxHellos = 5

	// CloseSize is the exact size of a CLOSE. DataOverhead is what a DATA
	// adds to the KCP packet it carries: the 16-byte header and the tag.
	CloseSize    = 32
	DataOverhead = 32

	// KCPMTU is the KCP MTU of every path session and the largest KCP packet
	// a DATA carries. MaxDatagram, the largest DATA, fits the IPv6 minimum
	// MTU.
	KCPMTU      = 1200
	MaxDatagram = KCPMTU + DataOverhead

	// ReplayWindow is how many packets behind the highest counter seen a
	// DATA or CLOSE may arrive and still be accepted once.
	ReplayWindow = 2048

	// PathInbound is how many opened KCP packets a path holds for ReadFrom.
	// A packet that finds the queue full is dropped.
	PathInbound = 128
)

// knockKeyLen is the size of a knock key.
const knockKeyLen = 32

var (
	// ErrBadAddr is returned by [Dial] for an address that cannot be dialed:
	// an unspecified, multicast or broadcast address, or port 0.
	ErrBadAddr = errors.New("udp path: address cannot be dialed")

	// ErrPathClosed is returned by a closed path. It wraps [net.ErrClosed],
	// so kamune reads it as a dropped connection.
	ErrPathClosed = fmt.Errorf("udp path closed: %w", net.ErrClosed)

	// errPacketSize is a KCP packet that a DATA cannot carry.
	errPacketSize = fmt.Errorf(
		"udp path: kcp packet must be 1 to %d bytes", KCPMTU,
	)
)

// Config configures one end of the path layer.
type Config struct {
	// KnockKey is nil or a 32-byte key that both peers hold. With it, a
	// listener ignores HELLO and INIT from anyone without the key, and a
	// dialer fills the mac1 field of the packets it sends.
	KnockKey []byte
}

func (c Config) validate() error {
	if c.KnockKey != nil && len(c.KnockKey) != knockKeyLen {
		return fmt.Errorf(
			"udp path: knock key is %d bytes, not %d",
			len(c.KnockKey), knockKeyLen,
		)
	}
	return nil
}
