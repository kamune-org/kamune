package udppath

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"
)

const (
	// helloFirstDelay is the wait after the first HELLO. It doubles after
	// each one, so HELLOs go out at 0, 0.5, 1.5, 3.5 and 7.5 s.
	helloFirstDelay = 500 * time.Millisecond

	// initFirstDelay and initMaxDelay bound the INIT retransmit timer, which
	// doubles after each send.
	initFirstDelay = 250 * time.Millisecond
	initMaxDelay   = 2 * time.Second

	// initTries is how many times one INIT is sent before the dialer starts
	// again with a new client id.
	initTries = 3

	// cookieUseLimit is the age after which the dialer stops resending an
	// INIT with its cookie and starts again. It is below CookieLifetime, so
	// a resent INIT still reaches the server with a valid cookie.
	cookieUseLimit = 8 * time.Second

	// readBufSize holds any UDP datagram, so an oversize one is read whole
	// and dropped instead of failing the read.
	readBufSize = 65536

	// maxReadErrors is how many read errors in a row pass before the reader
	// waits between reads, from minErrBackoff doubling to maxErrBackoff.
	maxReadErrors = 64
	minErrBackoff = 5 * time.Millisecond
	maxErrBackoff = time.Second
)

// dialStep is the state of the dialer.
type dialStep uint8

const (
	helloSent dialStep = iota + 1
	initSent
)

// dialer is the state of one Dial.
type dialer struct {
	pc       net.PacketConn
	priv     *ecdh.PrivateKey // c_eph, while INIT_SENT
	raddrUDP *net.UDPAddr
	nextAt   time.Time // when the retransmit timer fires; zero is never
	cookieAt time.Time
	raddr    netip.AddrPort
	knock    []byte
	initPkt  []byte
	delay    time.Duration
	budget   int // HELLOs left before a COOKIE
	tries    int // sends of initPkt
	cookie   [cookieLen]byte
	cid      uint32
	step     dialStep
}

// Dial runs the client side of the path handshake to raddr on pc and returns
// the established path. It reads pc with read deadlines and clears the read
// deadline before it returns, on success and on every error. On error pc
// stays the caller's.
//
// HELLOs go out at 0, 0.5, 1.5, 3.5 and 7.5 s: at most [MaxHellos] reach an
// address that has not answered with a COOKIE, and each COOKIE refills that
// budget. An INIT is resent after 250 ms, doubling to 2 s. After three sends,
// or once its cookie is 8 s old, the dialer starts again with a new client
// id. Dial runs until the path is established, a write to pc fails, or ctx
// ends; the error then wraps ctx.Err().
func Dial(
	ctx context.Context, pc net.PacketConn, raddr netip.AddrPort, cfg Config,
) (*Path, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if err := checkTarget(raddr); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("udp path handshake: %w", err)
	}
	raddr = unmap(raddr)
	d := &dialer{
		pc:       pc,
		raddr:    raddr,
		raddrUDP: net.UDPAddrFromAddrPort(raddr),
		knock:    cfg.KnockKey,
		budget:   MaxHellos,
	}
	dl := newReadDeadline(ctx, pc)
	defer dl.finish()

	if err := d.startHello(time.Now()); err != nil {
		return nil, err
	}
	buf := make([]byte, readBufSize)
	errs := 0
	var backoff time.Duration
	for {
		if err := dl.set(d.nextAt); err != nil {
			return nil, fmt.Errorf("udp path handshake: %w", err)
		}
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return nil, fmt.Errorf("udp path handshake: %w", cerr)
			}
			switch {
			case errors.Is(err, net.ErrClosed):
				return nil, fmt.Errorf("udp path handshake: %w", err)
			case errors.Is(err, os.ErrDeadlineExceeded):
				if err = d.onTimer(time.Now()); err != nil {
					return nil, err
				}
			default:
				// Every other read error is transient, as ICMP-driven
				// errors on Windows are.
				if errs++; errs >= maxReadErrors {
					backoff = nextBackoff(backoff)
					if !pause(ctx, backoff) {
						return nil, fmt.Errorf(
							"udp path handshake: %w", ctx.Err(),
						)
					}
				}
			}
			continue
		}
		errs, backoff = 0, 0
		if src, ok := udpSource(from); !ok || src != d.raddr {
			continue
		}
		p, err := d.onPacket(buf[:n], time.Now())
		if err != nil {
			return nil, err
		}
		if p != nil {
			return p, nil
		}
	}
}

// checkTarget refuses an address that a dialer must not send to.
func checkTarget(ap netip.AddrPort) error {
	a := ap.Addr().Unmap()
	switch {
	case !ap.IsValid(), ap.Port() == 0, a.IsUnspecified(), a.IsMulticast(),
		a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return fmt.Errorf("%w: %s", ErrBadAddr, ap)
	}
	return nil
}

// startHello picks a new client id and sends its first HELLO.
func (d *dialer) startHello(now time.Time) error {
	d.step = helloSent
	d.priv = nil
	d.initPkt = nil
	d.cid = randomID()
	d.delay = helloFirstDelay
	return d.sendHello(now)
}

// sendHello sends a HELLO if the budget allows and arms the timer. With no
// budget left it sends nothing and waits for a COOKIE or for ctx.
func (d *dialer) sendHello(now time.Time) error {
	if d.budget == 0 {
		d.nextAt = time.Time{}
		return nil
	}
	d.budget--
	if err := d.write(encodeHello(d.cid, d.knock)); err != nil {
		return err
	}
	d.nextAt = now.Add(d.delay)
	d.delay *= 2
	return nil
}

func (d *dialer) onTimer(now time.Time) error {
	if d.nextAt.IsZero() || now.Before(d.nextAt) {
		return nil
	}
	if d.step == helloSent {
		return d.sendHello(now)
	}
	if d.tries >= initTries || now.Sub(d.cookieAt) > cookieUseLimit {
		return d.startHello(now)
	}
	if err := d.write(d.initPkt); err != nil {
		return err
	}
	d.tries++
	d.delay = min(2*d.delay, initMaxDelay)
	d.nextAt = now.Add(d.delay)
	return nil
}

// onPacket handles a datagram from the target. It returns the path once an
// ACCEPT verifies, and ignores every packet it does not expect.
func (d *dialer) onPacket(pkt []byte, now time.Time) (*Path, error) {
	if len(pkt) < headerLen {
		return nil, nil
	}
	switch {
	case pkt[0] == typeCookie && d.step == helloSent:
		m, err := parseCookie(pkt)
		if err != nil || m.cid != d.cid {
			return nil, nil
		}
		return nil, d.sendInit(m.cookie, now)
	case pkt[0] == typeAccept && d.step == initSent:
		m, err := parseAccept(pkt)
		if err != nil || m.cid != d.cid {
			return nil, nil
		}
		keys, err := clientKeys(d.priv, d.cookie, pkt, m)
		if err != nil {
			return nil, nil
		}
		return newPath(roleClient, d.raddr, d.cid, m.sid, keys), nil
	}
	return nil, nil
}

// sendInit answers a COOKIE: it refills the HELLO budget, draws c_eph and
// sends the first INIT.
func (d *dialer) sendInit(cookie [cookieLen]byte, now time.Time) error {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("udp path client key: %w", err)
	}
	d.step = initSent
	d.cookie = cookie
	d.cookieAt = now
	d.budget = MaxHellos
	d.priv = priv
	d.initPkt = encodeInit(d.cid, cookie, priv.PublicKey().Bytes(), d.knock)
	if err = d.write(d.initPkt); err != nil {
		return err
	}
	d.tries = 1
	d.delay = initFirstDelay
	d.nextAt = now.Add(d.delay)
	return nil
}

func (d *dialer) write(pkt []byte) error {
	if _, err := d.pc.WriteTo(pkt, d.raddrUDP); err != nil {
		return fmt.Errorf("udp path handshake: %w", err)
	}
	return nil
}

// readDeadline sets the read deadline of pc for Dial. Once ctx ends it keeps
// the deadline in the past, so a blocked read returns, and finish clears it.
type readDeadline struct {
	pc       net.PacketConn
	stop     func() bool
	mu       sync.Mutex
	ended    bool
	finished bool
}

func newReadDeadline(ctx context.Context, pc net.PacketConn) *readDeadline {
	r := &readDeadline{pc: pc}
	r.stop = context.AfterFunc(ctx, func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.finished {
			return
		}
		r.ended = true
		_ = r.pc.SetReadDeadline(time.Unix(1, 0))
	})
	return r
}

// set sets the read deadline to t, zero for none, unless ctx has ended.
func (r *readDeadline) set(t time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ended {
		return nil
	}
	return r.pc.SetReadDeadline(t)
}

// finish clears the read deadline. A ctx that ends later changes nothing.
func (r *readDeadline) finish() {
	r.stop()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.finished = true
	_ = r.pc.SetReadDeadline(time.Time{})
}

// nextBackoff returns the wait after a run of read errors that followed a
// wait of prev.
func nextBackoff(prev time.Duration) time.Duration {
	if prev <= 0 {
		return minErrBackoff
	}
	return min(2*prev, maxErrBackoff)
}

// pause waits for d and reports true, or reports false once ctx ends.
func pause(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}
