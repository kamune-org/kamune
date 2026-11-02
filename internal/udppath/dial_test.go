package udppath

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/internal/udppath/udptest"
)

// hsEvent is one HELLO or INIT that the test responder received.
type hsEvent struct {
	at     time.Time
	cookie [cookieLen]byte
	cid    uint32
	typ    byte
}

// accepted is one ACCEPT that the test responder sent.
type accepted struct {
	out acceptOut
	sid uint32
}

// responder is the server half of the path handshake, built from the same
// functions the server uses, for testing Dial.
type responder struct {
	pc       net.PacketConn
	events   chan hsEvent
	accepted chan accepted
	secret   []byte
	// dropInit answers no INIT.
	dropInit bool
	// cookieOnInit sends a COOKIE under another secret before each ACCEPT.
	cookieOnInit bool
	// badFirst sends an ACCEPT with a flipped tag bit before each ACCEPT.
	badFirst bool
}

func startResponder(
	t *testing.T, n *udptest.Net, configure func(*responder),
) *responder {
	t.Helper()
	pc, err := n.Listen("127.0.0.1:0")
	require.New(t).NoError(err)
	r := &responder{
		pc:       pc,
		events:   make(chan hsEvent, 256),
		accepted: make(chan accepted, 16),
		secret:   bytes.Repeat([]byte{9}, 32),
	}
	if configure != nil {
		configure(r)
	}
	go r.run()
	t.Cleanup(func() { _ = pc.Close() })
	return r
}

func (r *responder) addr() netip.AddrPort {
	return r.pc.LocalAddr().(*net.UDPAddr).AddrPort()
}

func (r *responder) note(e hsEvent) {
	select {
	case r.events <- e:
	default:
	}
}

func (r *responder) run() {
	buf := make([]byte, readBufSize)
	for {
		n, from, err := r.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		src, ok := udpSource(from)
		if !ok || n == 0 {
			continue
		}
		pkt := buf[:n]
		now := time.Now()
		switch pkt[0] {
		case typeHello:
			m, err := parseHello(pkt)
			if err != nil {
				continue
			}
			r.note(hsEvent{at: now, cid: m.cid, typ: typeHello})
			c := makeCookie(r.secret, now, m.cid, src)
			_, _ = r.pc.WriteTo(encodeCookie(m.cid, c), from)
		case typeInit:
			m, err := parseInit(pkt)
			if err != nil {
				continue
			}
			r.note(hsEvent{
				at: now, cid: m.cid, cookie: m.cookie, typ: typeInit,
			})
			if r.dropInit || !validCookie(r.secret, m.cookie, m.cid, src, now) {
				continue
			}
			if r.cookieOnInit {
				other := bytes.Repeat([]byte{10}, 32)
				c := makeCookie(other, now, m.cid, src)
				_, _ = r.pc.WriteTo(encodeCookie(m.cid, c), from)
			}
			sid := randomID()
			out, err := responderAccept(m, sid)
			if err != nil {
				continue
			}
			if r.badFirst {
				bad := bytes.Clone(out.pkt)
				bad[AcceptSize-1] ^= 1
				_, _ = r.pc.WriteTo(bad, from)
			}
			_, _ = r.pc.WriteTo(out.pkt, from)
			select {
			case r.accepted <- accepted{out: out, sid: sid}:
			default:
			}
		}
	}
}

// keysFor returns the keys of the ACCEPT the responder sent for sid.
func (r *responder) keysFor(t *testing.T, sid uint32) pathKeys {
	t.Helper()
	for {
		select {
		case acc := <-r.accepted:
			if acc.sid == sid {
				return acc.out.keys
			}
		case <-time.After(time.Second):
			require.New(t).FailNow("no ACCEPT for the path's sid")
		}
	}
}

func dialPC(t *testing.T, n *udptest.Net) net.PacketConn {
	t.Helper()
	pc, err := n.Listen("127.0.0.1:0")
	require.New(t).NoError(err)
	t.Cleanup(func() { _ = pc.Close() })
	return pc
}

func testCtx(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

// checkKeys checks that p and the responder hold the same path keys.
func checkKeys(t *testing.T, p *Path, keys pathKeys) {
	t.Helper()
	a := require.New(t)
	n := nonce(1)
	sealed := p.send.Seal(nil, n[:], []byte("c2s"), nil)
	opened, err := keys.c2s.Open(nil, n[:], sealed, nil)
	a.NoError(err)
	a.Equal([]byte("c2s"), opened)
	sealed = keys.s2c.Seal(nil, n[:], []byte("s2c"), nil)
	opened, err = p.recv.Open(nil, n[:], sealed, nil)
	a.NoError(err)
	a.Equal([]byte("s2c"), opened)
}

func TestDial(t *testing.T) {
	tests := []struct {
		configure func(*responder)
		name      string
	}{
		{name: "plain"},
		{name: "cookie ignored after init", configure: func(r *responder) {
			r.cookieOnInit = true
		}},
		{name: "bad accept tag ignored", configure: func(r *responder) {
			r.badFirst = true
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			n := udptest.New()
			r := startResponder(t, n, tc.configure)
			pc := dialPC(t, n)

			p, err := Dial(testCtx(t, 5*time.Second), pc, r.addr(), Config{})
			a.NoError(err)
			a.Equal(r.addr(), p.RemoteAddr())
			a.Equal(r.addr().String(), p.RemoteUDPAddr().String())
			a.Same(p.RemoteUDPAddr(), p.RemoteUDPAddr())
			a.NotZero(p.Conv())
			checkKeys(t, p, r.keysFor(t, p.sid))

			// Every INIT carries the first cookie, so the second COOKIE
			// started nothing.
			var first [cookieLen]byte
			for len(r.events) > 0 {
				e := <-r.events
				if e.typ != typeInit {
					continue
				}
				if first == ([cookieLen]byte{}) {
					first = e.cookie
				}
				a.Equal(first, e.cookie)
				a.Equal(p.Conv(), e.cid)
			}
		})
	}
}

func TestDialMappedTarget(t *testing.T) {
	a := require.New(t)
	n := udptest.New()
	r := startResponder(t, n, nil)
	pc := dialPC(t, n)
	ap := r.addr()
	mapped := netip.AddrPortFrom(netip.AddrFrom16(ap.Addr().As16()), ap.Port())

	p, err := Dial(testCtx(t, 5*time.Second), pc, mapped, Config{})
	a.NoError(err)
	a.Equal(ap, p.RemoteAddr())
}

func TestDialRestartsAfterThreeInits(t *testing.T) {
	a := require.New(t)
	n := udptest.New()
	r := startResponder(t, n, func(r *responder) { r.dropInit = true })
	pc := dialPC(t, n)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		_, err := Dial(ctx, pc, r.addr(), Config{})
		errc <- err
	}()

	var seen []hsEvent
	deadline := time.After(5 * time.Second)
	for len(seen) < 5 {
		select {
		case e := <-r.events:
			seen = append(seen, e)
		case <-deadline:
			a.FailNow("dialer did not restart", "saw %d packets", len(seen))
		}
	}
	cancel()
	a.ErrorIs(<-errc, context.Canceled)

	a.Equal(byte(typeHello), seen[0].typ)
	for _, e := range seen[1:4] {
		a.Equal(byte(typeInit), e.typ)
		a.Equal(seen[0].cid, e.cid)
	}
	a.Equal(byte(typeHello), seen[4].typ)
	a.NotEqual(seen[0].cid, seen[4].cid)
	gap := seen[4].at.Sub(seen[1].at)
	a.InDelta(float64(1750*time.Millisecond), float64(gap),
		float64(500*time.Millisecond))
}

func TestDialContextEnds(t *testing.T) {
	t.Run("deadline", func(t *testing.T) {
		a := require.New(t)
		n := udptest.New()
		sink := dialPC(t, n)
		pc := dialPC(t, n)
		target := sink.LocalAddr().(*net.UDPAddr).AddrPort()
		_, err := Dial(testCtx(t, 200*time.Millisecond), pc, target, Config{})
		a.ErrorIs(err, context.DeadlineExceeded)
	})
	t.Run("cancel", func(t *testing.T) {
		a := require.New(t)
		n := udptest.New()
		sink := dialPC(t, n)
		pc := dialPC(t, n)
		target := sink.LocalAddr().(*net.UDPAddr).AddrPort()
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(100*time.Millisecond, cancel)
		_, err := Dial(ctx, pc, target, Config{})
		a.ErrorIs(err, context.Canceled)
		a.NotErrorIs(err, context.DeadlineExceeded)
	})
	t.Run("already done", func(t *testing.T) {
		a := require.New(t)
		n := udptest.New()
		sink := dialPC(t, n)
		pc := dialPC(t, n)
		target := sink.LocalAddr().(*net.UDPAddr).AddrPort()
		var sent atomic.Int32
		n.SetFilter(func(_, _ netip.AddrPort, _ []byte) int {
			sent.Add(1)
			return 1
		})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := Dial(ctx, pc, target, Config{})
		a.ErrorIs(err, context.Canceled)
		a.Zero(sent.Load())
	})
}

// deadlineRecorder records the read deadlines set on a PacketConn.
type deadlineRecorder struct {
	net.PacketConn
	last  time.Time
	mu    sync.Mutex
	calls int
}

func (d *deadlineRecorder) SetReadDeadline(t time.Time) error {
	d.mu.Lock()
	d.last = t
	d.calls++
	d.mu.Unlock()
	return d.PacketConn.SetReadDeadline(t)
}

func (d *deadlineRecorder) lastDeadline() (time.Time, int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.last, d.calls
}

func TestDialClearsReadDeadline(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		a := require.New(t)
		n := udptest.New()
		r := startResponder(t, n, nil)
		pc := &deadlineRecorder{PacketConn: dialPC(t, n)}
		_, err := Dial(testCtx(t, 5*time.Second), pc, r.addr(), Config{})
		a.NoError(err)
		last, calls := pc.lastDeadline()
		a.Positive(calls)
		a.True(last.IsZero())
	})
	t.Run("failure", func(t *testing.T) {
		a := require.New(t)
		n := udptest.New()
		sink := dialPC(t, n)
		pc := &deadlineRecorder{PacketConn: dialPC(t, n)}
		target := sink.LocalAddr().(*net.UDPAddr).AddrPort()
		_, err := Dial(testCtx(t, 200*time.Millisecond), pc, target, Config{})
		a.Error(err)
		last, calls := pc.lastDeadline()
		a.Positive(calls)
		a.True(last.IsZero())
	})
}

func TestDialBadInput(t *testing.T) {
	tests := []struct {
		target string
		name   string
		knock  []byte
		badArg error
	}{
		{name: "unspecified", target: "0.0.0.0:1", badArg: ErrBadAddr},
		{name: "unspecified v6", target: "[::]:1", badArg: ErrBadAddr},
		{name: "multicast", target: "224.0.0.1:1", badArg: ErrBadAddr},
		{name: "multicast v6", target: "[ff02::1]:1", badArg: ErrBadAddr},
		{name: "broadcast", target: "255.255.255.255:1", badArg: ErrBadAddr},
		{name: "mapped broadcast", target: "[::ffff:255.255.255.255]:1",
			badArg: ErrBadAddr},
		{name: "port zero", target: "192.0.2.1:0", badArg: ErrBadAddr},
		{name: "short knock key", target: "192.0.2.1:1", knock: []byte{1}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			n := udptest.New()
			var sent atomic.Int32
			n.SetFilter(func(_, _ netip.AddrPort, _ []byte) int {
				sent.Add(1)
				return 1
			})
			pc := dialPC(t, n)
			target := netip.MustParseAddrPort(tc.target)
			_, err := Dial(
				testCtx(t, time.Second), pc, target, Config{KnockKey: tc.knock},
			)
			a.Error(err)
			if tc.badArg != nil {
				a.ErrorIs(err, tc.badArg)
			}
			a.Zero(sent.Load())
		})
	}
	t.Run("loopback and link-local allowed", func(t *testing.T) {
		a := require.New(t)
		a.NoError(checkTarget(netip.MustParseAddrPort("127.0.0.1:1")))
		a.NoError(checkTarget(netip.MustParseAddrPort("[fe80::1]:1")))
	})
}

func TestDialClosedConn(t *testing.T) {
	a := require.New(t)
	n := udptest.New()
	sink := dialPC(t, n)
	pc := dialPC(t, n)
	target := sink.LocalAddr().(*net.UDPAddr).AddrPort()
	time.AfterFunc(100*time.Millisecond, func() { _ = pc.Close() })
	_, err := Dial(testCtx(t, 5*time.Second), pc, target, Config{})
	a.ErrorIs(err, net.ErrClosed)
}

// flakyReader fails the first fail reads with a transient error.
type flakyReader struct {
	net.PacketConn
	fail atomic.Int32
}

func (f *flakyReader) ReadFrom(b []byte) (int, net.Addr, error) {
	if f.fail.Add(-1) >= 0 {
		return 0, nil, syscall.ECONNRESET
	}
	return f.PacketConn.ReadFrom(b)
}

func TestDialSurvivesReadErrors(t *testing.T) {
	a := require.New(t)
	n := udptest.New()
	r := startResponder(t, n, nil)
	pc := &flakyReader{PacketConn: dialPC(t, n)}
	pc.fail.Store(maxReadErrors + 6)
	p, err := Dial(testCtx(t, 5*time.Second), pc, r.addr(), Config{})
	a.NoError(err)
	checkKeys(t, p, r.keysFor(t, p.sid))
}

func TestDialKnockKey(t *testing.T) {
	a := require.New(t)
	n := udptest.New()
	key := bytes.Repeat([]byte{4}, knockKeyLen)
	r := startResponder(t, n, nil)
	var bad atomic.Int32
	n.SetFilter(func(_, to netip.AddrPort, pkt []byte) int {
		if to != r.addr() {
			return 1
		}
		switch pkt[0] {
		case typeHello:
			m, err := parseHello(pkt)
			if err != nil || !checkKnock(key, m.mac1, pkt[:helloMAC1]) {
				bad.Add(1)
			}
		case typeInit:
			m, err := parseInit(pkt)
			if err != nil || !checkKnock(key, m.mac1, pkt[:initMAC1]) {
				bad.Add(1)
			}
		}
		return 1
	})
	pc := dialPC(t, n)
	_, err := Dial(
		testCtx(t, 5*time.Second), pc, r.addr(), Config{KnockKey: key},
	)
	a.NoError(err)
	a.Zero(bad.Load())
}

func TestDialHelloBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("takes about 9 seconds")
	}
	a := require.New(t)
	n := udptest.New()
	sink := dialPC(t, n)
	target := sink.LocalAddr().(*net.UDPAddr).AddrPort()
	var hellos, bytesSent atomic.Int64
	n.SetFilter(func(_, to netip.AddrPort, pkt []byte) int {
		if to == target {
			bytesSent.Add(int64(len(pkt)))
			if len(pkt) > 0 && pkt[0] == typeHello {
				hellos.Add(1)
			}
		}
		return 1
	})
	pc := dialPC(t, n)
	_, err := Dial(testCtx(t, 9*time.Second), pc, target, Config{})
	a.True(errors.Is(err, context.DeadlineExceeded))
	a.Equal(int64(MaxHellos), hellos.Load())
	a.Equal(int64(MaxHellos*HelloSize), bytesSent.Load())
}
