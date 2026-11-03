package kamune

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/xtaci/kcp-go/v5"

	"github.com/kamune-org/kamune/internal/clock"
	"github.com/kamune-org/kamune/internal/udppath"
)

// udpKnockKeyLen is the size of a knock key.
const udpKnockKeyLen = 32

// Bounds of the linger that [kcpPath.Close] waits before it ends a session
// whose reads and writes have not failed. The wait is three times the smoothed
// round-trip time of the session, within these bounds, so that the close frame
// still queued in kcp-go reaches the peer before the path sends CLOSE.
const (
	minCloseLinger = 50 * time.Millisecond
	maxCloseLinger = time.Second
)

// UDPOption configures [ListenUDP], [DialUDP], [ServeWithUDP] and
// [DialWithUDP]. An option that returns an error makes the call that applies
// it fail.
type UDPOption func(*udpConfig) error

// udpConfig is what the UDP options set.
type udpConfig struct {
	clock    clock.Clock
	allow    func(from netip.AddrPort) bool
	knock    []byte
	connOpts []ConnOption
	limits   udppath.Limits
}

// newUDPConfig applies opts in order to a new config.
func newUDPConfig(opts []UDPOption) (*udpConfig, error) {
	cfg := &udpConfig{}
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

// UDPWithConnOptions sets the options of each [Conn] made over UDP.
func UDPWithConnOptions(opts ...ConnOption) UDPOption {
	return func(cfg *udpConfig) error {
		cfg.connOpts = append(cfg.connOpts, opts...)
		return nil
	}
}

// UDPWithSourceFilter sets a function that a server asks about the source of
// every HELLO and INIT it reads. A source that the function refuses gets no
// reply. A dialer ignores it.
func UDPWithSourceFilter(fn func(from netip.AddrPort) bool) UDPOption {
	return func(cfg *udpConfig) error {
		cfg.allow = fn
		return nil
	}
}

// UDPWithKnockKey sets the knock key that both peers hold. A server ignores
// every HELLO and INIT that lacks it, and a dialer fills it in. key must be 32
// bytes.
func UDPWithKnockKey(key []byte) UDPOption {
	return func(cfg *udpConfig) error {
		if len(key) != udpKnockKeyLen {
			return fmt.Errorf(
				"udp knock key is %d bytes, not %d",
				len(key), udpKnockKeyLen,
			)
		}
		cfg.knock = append([]byte(nil), key...)
		return nil
	}
}

// UDPPathLimits bounds the paths that a UDP server keeps and admits. A zero
// field takes its default, and a negative value of a per-source or per-network
// field means no limit.
type UDPPathLimits struct {
	// MaxPaths caps the paths in every state, default 4096.
	MaxPaths int
	// MaxPathsPerSource caps the paths of one source address, default 32.
	MaxPathsPerSource int
	// MaxPathsPerNetwork caps the paths of one IPv4 /24 or IPv6 /48, default
	// 128.
	MaxPathsPerNetwork int
	// MaxPending caps the paths that wait for their first DATA or for Accept,
	// default 256.
	MaxPending int
	// MaxPendingPerSource caps the pending paths of one source address,
	// default 4.
	MaxPendingPerSource int
}

// UDPWithPathLimits sets the limits of the paths that a UDP server keeps. A
// dialer ignores it.
func UDPWithPathLimits(l UDPPathLimits) UDPOption {
	return func(cfg *udpConfig) error {
		cfg.limits = udppath.Limits{
			MaxPaths:            l.MaxPaths,
			MaxPathsPerSource:   l.MaxPathsPerSource,
			MaxPathsPerNetwork:  l.MaxPathsPerNetwork,
			MaxPending:          l.MaxPending,
			MaxPendingPerSource: l.MaxPendingPerSource,
		}
		return nil
	}
}

// ListenUDP runs the path layer on pc and returns a Listener for
// [ServeWithListener]. It takes over reading and closing pc and clears its
// deadlines first. Callers may still call pc.WriteTo, as a NAT kick does. On
// error pc stays the caller's.
func ListenUDP(pc net.PacketConn, opts ...UDPOption) (Listener, error) {
	cfg, err := newUDPConfig(opts)
	if err != nil {
		return nil, err
	}
	return listenUDP(pc, cfg)
}

// listenUDP is [ListenUDP] with the options already applied.
func listenUDP(pc net.PacketConn, cfg *udpConfig) (Listener, error) {
	if err := pc.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("udp path listener: %w", err)
	}
	srv, err := udppath.NewServer(pc, udppath.Config{
		Clock:    cfg.clock,
		Allow:    cfg.allow,
		KnockKey: cfg.knock,
		Limits:   cfg.limits,
	})
	if err != nil {
		return nil, fmt.Errorf("udp path listener: %w", err)
	}
	return &pathListener{srv: srv, connOpts: cfg.connOpts}, nil
}

// DialUDP runs the path handshake to raddr on pc and starts a KCP session. It
// returns an error wrapping [ErrUDPHandshakeTimeout] when the deadline of ctx
// passes first. On a handshake error pc stays the caller's, with its read
// deadline cleared. Once the handshake succeeds, pc belongs to the returned
// Conn: closing the Conn closes pc, even when the KCP setup after the
// handshake fails.
func DialUDP(
	ctx context.Context,
	pc net.PacketConn,
	raddr netip.AddrPort,
	opts ...UDPOption,
) (Conn, error) {
	cfg, err := newUDPConfig(opts)
	if err != nil {
		return nil, err
	}
	return dialUDP(ctx, pc, raddr, cfg)
}

// dialUDP is [DialUDP] with the options already applied.
func dialUDP(
	ctx context.Context,
	pc net.PacketConn,
	raddr netip.AddrPort,
	cfg *udpConfig,
) (Conn, error) {
	p, err := udppath.Dial(
		ctx, pc, raddr, udppath.Config{KnockKey: cfg.knock},
	)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) &&
			errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("%w: %w", ErrUDPHandshakeTimeout, err)
		}
		return nil, fmt.Errorf("udp path dial: %w", err)
	}
	sess, err := newPathSession(p)
	if err != nil {
		_ = p.Close()
		return nil, err
	}
	return newConn(sess, cfg.connOpts...), nil
}

// newPathSession starts the KCP session of an established path. The MTU is set
// before the path starts, so that no packet is read or written at kcp-go's
// default MTU.
func newPathSession(p *udppath.Path) (*kcpPath, error) {
	sess, err := kcp.NewConn4(
		p.Conv(), p.RemoteUDPAddr(), nil, 0, 0, true, p,
	)
	if err != nil {
		return nil, fmt.Errorf("udp kcp session: %w", err)
	}
	sess.SetMtu(udppath.KCPMTU)
	// kcp-go otherwise holds each ACK until its next update tick, and the
	// congestion window then holds back a close frame queued behind unacked
	// data. The close linger could end before that frame leaves, so ACKs go
	// out at once.
	sess.SetACKNoDelay(true)
	p.Start()
	return &kcpPath{UDPSession: sess, path: p}, nil
}

// pathListener is the Listener of [ListenUDP]. It turns each path that the
// server accepts into a Conn.
type pathListener struct {
	srv      *udppath.Server
	connOpts []ConnOption
}

// Accept returns the Conn of the next path. A path whose KCP session cannot be
// set up is closed, and Accept waits for the next one.
func (l *pathListener) Accept() (Conn, error) {
	for {
		p, err := l.srv.Accept()
		if err != nil {
			return nil, err
		}
		sess, err := newPathSession(p)
		if err != nil {
			_ = p.Close()
			continue
		}
		return newConn(sess, l.connOpts...), nil
	}
}

// Close closes the server. Its paths that Accept has not returned are closed,
// and the socket closes with the last path that Accept returned.
func (l *pathListener) Close() error {
	return l.srv.Close()
}

// kcpPath is the net.Conn of one KCP session over a path. It records the first
// failed read or write, which ends the close linger early, and it maps a
// closed path to [ErrConnClosed].
type kcpPath struct {
	*kcp.UDPSession
	path   *udppath.Path
	failed atomic.Bool
	closed atomic.Bool
}

// Read reads from the session.
func (c *kcpPath) Read(b []byte) (int, error) {
	n, err := c.UDPSession.Read(b)
	return n, c.check(err)
}

// Write writes to the session.
func (c *kcpPath) Write(b []byte) (int, error) {
	n, err := c.UDPSession.Write(b)
	return n, c.check(err)
}

// Close ends the session, and with it the path, which sends CLOSE to the peer.
// Unless a read or write has failed, it first waits for the close linger, so
// that the close frame reaches the peer. Close is safe to call more than once.
func (c *kcpPath) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return net.ErrClosed
	}
	if !c.failed.Load() {
		time.Sleep(closeLinger(c.GetSRTT()))
	}
	return c.UDPSession.Close()
}

// check records err if it is a failure, and maps an error of a closed path to
// [ErrConnClosed], which the caller can match. A timeout is not a failure: the
// session goes on after a deadline, so its close still lingers.
func (c *kcpPath) check(err error) error {
	if err == nil {
		return nil
	}
	if !isTimeout(err) {
		c.failed.Store(true)
	}
	if errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("%w: %w", ErrConnClosed, err)
	}
	return err
}

// closeLinger returns how long a session whose smoothed round-trip time is srtt
// milliseconds waits before it ends.
func closeLinger(srtt int32) time.Duration {
	d := 3 * time.Duration(srtt) * time.Millisecond
	return min(max(d, minCloseLinger), maxCloseLinger)
}
