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
	"net/netip"
	"time"

	"github.com/kamune-org/kamune/internal/clock"
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

	// HalfOpenTimeout is how long a server path waits, in HALF_OPEN, for the
	// first DATA of its client. QueuedTimeout is how long a QUEUED path waits
	// for [Server.Accept].
	HalfOpenTimeout = 5 * time.Second
	QueuedTimeout   = 10 * time.Second

	// HandshakeQueue is how many HELLO and INIT packets wait for the server's
	// handshake worker. A packet that finds the queue full is dropped.
	HandshakeQueue = 256
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

	// ErrListenerClosed is returned by [Server.Accept] once the server is
	// closed. It wraps [net.ErrClosed].
	ErrListenerClosed = fmt.Errorf(
		"udp path listener closed: %w", net.ErrClosed,
	)

	// errPacketSize is a KCP packet that a DATA cannot carry.
	errPacketSize = fmt.Errorf(
		"udp path: kcp packet must be 1 to %d bytes", KCPMTU,
	)
)

// Config configures one end of the path layer. The fields marked as
// server-only are read by [NewServer] and ignored by [Dial].
type Config struct {
	// Clock is the time source of a server, for cookies, timeouts and the
	// INIT limiter. Nil uses [clock.Real]. Server-only.
	Clock clock.Clock

	// Allow, when set, is asked about the source of every HELLO and INIT a
	// server reads. False drops the packet with no reply and counts it as
	// Filtered. Nil admits every source. Server-only. Allow runs on the
	// handshake worker, which Close waits for, so it must not block.
	Allow func(from netip.AddrPort) bool

	// KnockKey is nil or a 32-byte key that both peers hold. With it, a
	// listener ignores HELLO and INIT from anyone without the key, and a
	// dialer fills the mac1 field of the packets it sends.
	KnockKey []byte

	// Limits bounds the state and the admission of a server. Its zero value
	// is the default. Server-only.
	Limits Limits
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
