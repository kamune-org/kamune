package udppath

import (
	"bytes"
	"context"
	"crypto/ecdh"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/internal/admit"
	"github.com/kamune-org/kamune/internal/clock"
	"github.com/kamune-org/kamune/internal/udppath/udptest"
)

// testEpoch is where the fake clock of a test starts.
var testEpoch = time.Unix(1_800_000_000, 0)

// testClock returns a fake clock at testEpoch. Only the test moves it.
func testClock() *clock.Fake {
	return clock.NewFake(testEpoch)
}

// startServer starts a server on addr and closes it when the test ends.
func startServer(
	tb testing.TB, n *udptest.Net, addr string, cfg Config,
) *Server {
	tb.Helper()
	pc, err := n.Listen(addr)
	require.New(tb).NoError(err)
	s, err := NewServer(pc, cfg)
	require.New(tb).NoError(err)
	tb.Cleanup(func() { _ = s.Close() })
	return s
}

// listenAddr returns the address of the server's socket.
func listenAddr(s *Server) netip.AddrPort {
	return s.Addr().(*net.UDPAddr).AddrPort()
}

// pathCount returns how many paths the server holds, in any state.
func (s *Server) pathCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.paths)
}

// queuedCount returns how many paths wait in the accept queue.
func (s *Server) queuedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.acceptList)
}

// acceptWithin runs Accept and fails the test if it takes over a second.
func acceptWithin(tb testing.TB, s *Server) *Path {
	tb.Helper()
	type result struct {
		p   *Path
		err error
	}
	ch := make(chan result, 1)
	go func() {
		p, err := s.Accept()
		ch <- result{p: p, err: err}
	}()
	select {
	case r := <-ch:
		require.New(tb).NoError(r.err)
		return r.p
	case <-time.After(time.Second):
		require.New(tb).FailNow("Accept did not return")
		return nil
	}
}

// eventually polls cond until it holds, and fails the test after two seconds.
func eventually(tb testing.TB, cond func() bool, msg string) {
	tb.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			require.New(tb).FailNow(msg)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// newPrivate returns a fresh X25519 key for a client's c_eph.
func newPrivate(tb testing.TB) *ecdh.PrivateKey {
	tb.Helper()
	priv, err := ecdh.X25519().GenerateKey(crand.Reader)
	require.New(tb).NoError(err)
	return priv
}

// rawClient is a socket that runs the path handshake by hand. The test builds
// every packet it sends, and reads are synchronous with deadlines.
type rawClient struct {
	tb     testing.TB
	pc     net.PacketConn
	server netip.AddrPort
	// knock is the key of the HELLOs and INITs this client sends, or nil.
	knock []byte
}

// rawPath is a path that a rawClient established: its keys and both ids.
type rawPath struct {
	keys pathKeys
	cid  uint32
	sid  uint32
}

// newRawClient binds a socket on ip, on a free port, to talk to server.
func newRawClient(
	tb testing.TB, n *udptest.Net, ip string, server netip.AddrPort,
) *rawClient {
	tb.Helper()
	pc, err := n.Listen(ip + ":0")
	require.New(tb).NoError(err)
	tb.Cleanup(func() { _ = pc.Close() })
	return &rawClient{tb: tb, pc: pc, server: server}
}

func (c *rawClient) send(pkt []byte) {
	c.tb.Helper()
	_, err := c.pc.WriteTo(pkt, net.UDPAddrFromAddrPort(c.server))
	require.New(c.tb).NoError(err)
}

// next returns the next datagram the socket reads within d.
func (c *rawClient) next(d time.Duration) ([]byte, bool) {
	_ = c.pc.SetReadDeadline(time.Now().Add(d))
	buf := make([]byte, readBufSize)
	n, _, err := c.pc.ReadFrom(buf)
	if err != nil {
		return nil, false
	}
	return buf[:n], true
}

// await returns the first datagram within d that match accepts.
func (c *rawClient) await(
	d time.Duration, match func([]byte) bool,
) ([]byte, bool) {
	deadline := time.Now().Add(d)
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return nil, false
		}
		pkt, ok := c.next(left)
		if !ok {
			return nil, false
		}
		if match(pkt) {
			return pkt, true
		}
	}
}

// drain returns every datagram that arrives within d.
func (c *rawClient) drain(d time.Duration) [][]byte {
	var pkts [][]byte
	deadline := time.Now().Add(d)
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return pkts
		}
		pkt, ok := c.next(left)
		if !ok {
			return pkts
		}
		pkts = append(pkts, pkt)
	}
}

// dropHello sends a HELLO for cid and returns what arrives within 200 ms.
func (c *rawClient) dropHello(cid uint32) [][]byte {
	c.send(encodeHello(cid, c.knock))
	return c.drain(200 * time.Millisecond)
}

// cookie sends a HELLO for cid and returns the COOKIE that answers it.
func (c *rawClient) cookie(cid uint32) ([cookieLen]byte, bool) {
	var got cookieMsg
	c.send(encodeHello(cid, c.knock))
	_, ok := c.await(time.Second, func(p []byte) bool {
		m, err := parseCookie(p)
		got = m
		return err == nil && m.cid == cid
	})
	if !ok {
		return [cookieLen]byte{}, false
	}
	return got.cookie, true
}

// accept waits up to d for the ACCEPT of cid.
func (c *rawClient) accept(cid uint32, d time.Duration) ([]byte, bool) {
	return c.await(d, func(p []byte) bool {
		m, err := parseAccept(p)
		return err == nil && m.cid == cid
	})
}

// establish runs the whole handshake of cid by hand. The server path it makes
// is HALF_OPEN until the client sends DATA on it.
func (c *rawClient) establish(cid uint32) rawPath {
	c.tb.Helper()
	a := require.New(c.tb)
	cookie, ok := c.cookie(cid)
	a.True(ok, "no COOKIE for cid %d", cid)
	priv := newPrivate(c.tb)
	c.send(encodeInit(cid, cookie, priv.PublicKey().Bytes(), c.knock))
	pkt, ok := c.accept(cid, time.Second)
	a.True(ok, "no ACCEPT for cid %d", cid)
	m, err := parseAccept(pkt)
	a.NoError(err)
	keys, err := clientKeys(priv, cookie, pkt, m)
	a.NoError(err)
	return rawPath{keys: keys, cid: cid, sid: m.sid}
}

// initFor sends an INIT of cid with the cookie and a fresh c_eph, and returns
// the ACCEPT, if one arrives within 200 ms.
func (c *rawClient) initFor(cid uint32, cookie [cookieLen]byte) ([]byte, bool) {
	c.send(encodeInit(cid, cookie, newPrivate(c.tb).PublicKey().Bytes(), c.knock))
	return c.accept(cid, 200*time.Millisecond)
}

// data sends one DATA of rp with the counter ctr.
func (c *rawClient) data(rp rawPath, ctr uint64, payload []byte) {
	c.send(sealPacket(nil, rp.keys.c2s, typeData, rp.sid, ctr, payload))
}

// recv waits up to d for the next DATA of rp from the server and returns its
// payload.
func (c *rawClient) recv(rp rawPath, d time.Duration) ([]byte, bool) {
	var payload []byte
	_, ok := c.await(d, func(p []byte) bool {
		m, err := parseSealed(p)
		if err != nil || m.typ != typeData || m.rid != rp.cid {
			return false
		}
		plain, err := openPacket(nil, rp.keys.s2c, m.ctr, p)
		payload = plain
		return err == nil
	})
	return payload, ok
}

// closes counts the CLOSE packets that the server sent for rp within d.
func (c *rawClient) closes(rp rawPath, d time.Duration) int {
	deadline := time.Now().Add(d)
	n := 0
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return n
		}
		_, ok := c.await(left, func(p []byte) bool {
			return isCloseFor(p, rp)
		})
		if !ok {
			return n
		}
		n++
	}
}

// isCloseFor reports whether p is a CLOSE from the server for rp that opens.
func isCloseFor(p []byte, rp rawPath) bool {
	m, err := parseSealed(p)
	if err != nil || m.typ != typeClose || m.rid != rp.cid {
		return false
	}
	_, err = openPacket(nil, rp.keys.s2c, m.ctr, p)
	return err == nil
}

// countType returns how many of pkts have the packet type typ.
func countType(pkts [][]byte, typ byte) int {
	n := 0
	for _, p := range pkts {
		if len(p) > 0 && p[0] == typ {
			n++
		}
	}
	return n
}

// acceptsOf returns the ACCEPT packets of cid among pkts.
func acceptsOf(pkts [][]byte, cid uint32) [][]byte {
	var out [][]byte
	for _, p := range pkts {
		if m, err := parseAccept(p); err == nil && m.cid == cid {
			out = append(out, p)
		}
	}
	return out
}

// pathsByConv accepts n paths from s and returns them by their conv.
func pathsByConv(tb testing.TB, s *Server, n int) map[uint32]*Path {
	tb.Helper()
	out := make(map[uint32]*Path, n)
	for range n {
		p := acceptWithin(tb, s)
		out[p.Conv()] = p
	}
	return out
}

// usedIDs hands out client ids that no test has used yet.
type usedIDs map[uint32]bool

// next returns a random client id that is not in u yet, and marks it.
func (u usedIDs) next() uint32 {
	for {
		cid := randomID()
		if !u[cid] {
			u[cid] = true
			return cid
		}
	}
}

func TestLimitsResolve(t *testing.T) {
	a := require.New(t)
	r, err := Limits{}.resolve()
	a.NoError(err)
	a.Equal(resolvedLimits{
		initRate:            admit.Rate{PerSecond: 4, Burst: 8},
		maxPaths:            4096,
		maxPathsPerSource:   32,
		maxPathsPerNetwork:  128,
		maxPending:          256,
		maxPendingPerSource: 4,
	}, r)

	r, err = Limits{
		MaxPathsPerSource:   -1,
		MaxPathsPerNetwork:  -1,
		MaxPendingPerSource: -1,
	}.resolve()
	a.NoError(err)
	a.Equal(-1, r.maxPathsPerSource)
	a.Equal(-1, r.maxPathsPerNetwork)
	a.Equal(-1, r.maxPendingPerSource)
}

func TestNewServerConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		ok   bool
	}{
		{name: "zero", ok: true},
		{name: "no per-source limits", ok: true, cfg: Config{Limits: Limits{
			MaxPathsPerSource:   -1,
			MaxPathsPerNetwork:  -1,
			MaxPendingPerSource: -1,
		}}},
		{name: "disabled init rate", ok: true, cfg: Config{
			Limits: Limits{InitRate: admit.Rate{Burst: 1}},
		}},
		{name: "negative max paths", cfg: Config{
			Limits: Limits{MaxPaths: -1},
		}},
		{name: "negative max pending", cfg: Config{
			Limits: Limits{MaxPending: -1},
		}},
		{name: "negative rate", cfg: Config{Limits: Limits{
			InitRate: admit.Rate{PerSecond: -1, Burst: 1},
		}}},
		{name: "rate without burst", cfg: Config{Limits: Limits{
			InitRate: admit.Rate{PerSecond: 4},
		}}},
		{name: "short knock key", cfg: Config{KnockKey: []byte{1}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			pc := dialPC(t, udptest.New())
			s, err := NewServer(pc, tc.cfg)
			if !tc.ok {
				a.Error(err)
				a.Nil(s)
				return
			}
			a.NoError(err)
			a.NoError(s.Close())
		})
	}
}

func TestServerDialAccept(t *testing.T) {
	a := require.New(t)
	n := udptest.New()
	s := startServer(t, n, "203.0.113.10:0", Config{Clock: testClock()})
	pc := dialPC(t, n)
	client, err := Dial(
		testCtx(t, 5*time.Second), pc, listenAddr(s), Config{},
	)
	a.NoError(err)
	t.Cleanup(func() { _ = client.Close() })

	write(t, client, []byte("hello"))
	client.Start()
	sp := acceptWithin(t, s)
	a.Equal(client.Conv(), sp.Conv())
	a.Equal(
		client.LocalAddr().(*net.UDPAddr).AddrPort(), sp.RemoteAddr(),
	)
	sp.Start()
	res := readWithin(t, sp)
	a.NoError(res.err)
	a.Equal([]byte("hello"), res.data)

	write(t, sp, []byte("back"))
	res = readWithin(t, client)
	a.NoError(res.err)
	a.Equal([]byte("back"), res.data)
}

func TestServerInitValid(t *testing.T) {
	a := require.New(t)
	n := udptest.New()
	s := startServer(t, n, "203.0.113.10:0", Config{Clock: testClock()})
	c := newRawClient(t, n, "198.51.100.1", listenAddr(s))
	cid := randomID()
	cookie, ok := c.cookie(cid)
	a.True(ok)
	priv := newPrivate(t)
	initPkt := encodeInit(cid, cookie, priv.PublicKey().Bytes(), nil)
	c.send(initPkt)
	first, ok := c.accept(cid, time.Second)
	a.True(ok)
	a.Equal(1, s.pathCount())

	const resends = 20
	for range resends {
		c.send(initPkt)
	}
	got := acceptsOf(c.drain(300*time.Millisecond), cid)
	a.Len(got, resends)
	for _, pkt := range got {
		a.Equal(first, pkt, "a retransmit gets the same ACCEPT")
	}
	a.Equal(1, s.pathCount())
	a.Zero(s.Stats().RateLimited, "retransmits use no tokens")
}

func TestServerInitRefused(t *testing.T) {
	n := udptest.New()
	clk := testClock()
	s := startServer(t, n, "203.0.113.10:0", Config{Clock: clk})
	c := newRawClient(t, n, "198.51.100.1", listenAddr(s))
	used := usedIDs{}

	// The first subtest makes the one path the others must leave alone.
	var cookie [cookieLen]byte
	var cid uint32
	t.Run("valid", func(t *testing.T) {
		a := require.New(t)
		cid = used.next()
		var ok bool
		cookie, ok = c.cookie(cid)
		a.True(ok)
		_, ok = c.initFor(cid, cookie)
		a.True(ok)
		a.Equal(1, s.pathCount())
	})

	t.Run("same cid other c_eph", func(t *testing.T) {
		a := require.New(t)
		other := newPrivate(t)
		c.send(encodeInit(cid, cookie, other.PublicKey().Bytes(), nil))
		a.Zero(countType(c.drain(200*time.Millisecond), typeAccept))
		a.Equal(1, s.pathCount())
	})

	smallOrder := map[string][]byte{
		"zero": make([]byte, ephLen),
		"one":  append([]byte{1}, make([]byte, ephLen-1)...),
	}
	for name, eph := range smallOrder {
		t.Run("small order c_eph "+name, func(t *testing.T) {
			a := require.New(t)
			sid := used.next()
			ck, ok := c.cookie(sid)
			a.True(ok)
			before := s.Stats().Malformed
			c.send(encodeInit(sid, ck, eph, nil))
			a.Zero(countType(c.drain(200*time.Millisecond), typeAccept))
			a.Equal(before+1, s.Stats().Malformed)
			a.Equal(1, s.pathCount())
		})
	}

	t.Run("bad cookie", func(t *testing.T) {
		a := require.New(t)
		var bad [cookieLen]byte
		bad[10] = 1
		before := s.Stats().BadCookie
		_, ok := c.initFor(used.next(), bad)
		a.False(ok)
		a.Equal(before+1, s.Stats().BadCookie)
	})

	t.Run("cookie for another source", func(t *testing.T) {
		a := require.New(t)
		id := used.next()
		other := newRawClient(t, n, "198.51.100.2", listenAddr(s))
		ck, ok := other.cookie(id)
		a.True(ok)
		before := s.Stats().BadCookie
		_, ok = c.initFor(id, ck)
		a.False(ok)
		a.Equal(before+1, s.Stats().BadCookie)
	})

	t.Run("expired cookie", func(t *testing.T) {
		a := require.New(t)
		id := used.next()
		ck, ok := c.cookie(id)
		a.True(ok)
		clk.Advance(CookieLifetime + 2*time.Second)
		_, ok = c.initFor(id, ck)
		a.False(ok, "a cookie older than its lifetime is refused")
	})
}

func TestServerAllowFilter(t *testing.T) {
	a := require.New(t)
	n := udptest.New()
	var allow atomic.Bool
	allow.Store(true)
	s := startServer(t, n, "203.0.113.10:0", Config{
		Clock: testClock(),
		Allow: func(netip.AddrPort) bool { return allow.Load() },
	})
	c := newRawClient(t, n, "198.51.100.1", listenAddr(s))
	used := usedIDs{}
	cid := used.next()
	cookie, ok := c.cookie(cid)
	a.True(ok)

	allow.Store(false)
	a.Zero(countType(c.dropHello(used.next()), typeCookie))
	a.Equal(uint64(1), s.Stats().Filtered)

	_, ok = c.initFor(cid, cookie)
	a.False(ok)
	a.Equal(uint64(2), s.Stats().Filtered)
	a.Zero(s.pathCount())
}

func TestServerKnockHello(t *testing.T) {
	key := bytes.Repeat([]byte{4}, knockKeyLen)
	other := bytes.Repeat([]byte{5}, knockKeyLen)
	tests := []struct {
		name      string
		serverKey []byte
		helloKey  []byte
		cookie    bool
	}{
		{name: "no mac1", serverKey: key},
		{name: "wrong key", serverKey: key, helloKey: other},
		{name: "right key", serverKey: key, helloKey: key, cookie: true},
		{name: "no server key ignores mac1", helloKey: other, cookie: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			n := udptest.New()
			s := startServer(t, n, "203.0.113.10:0", Config{
				Clock:    testClock(),
				KnockKey: tc.serverKey,
			})
			c := newRawClient(t, n, "198.51.100.1", listenAddr(s))
			c.knock = tc.helloKey
			got := countType(
				c.dropHello(randomID()), typeCookie,
			)
			if tc.cookie {
				a.Equal(1, got)
				a.Equal(uint64(1), s.Stats().Hello)
				return
			}
			a.Zero(got)
			a.Zero(s.Stats().Hello)
			a.Equal(uint64(1), s.Stats().KnockFail)
		})
	}
}

func TestServerKnockInit(t *testing.T) {
	a := require.New(t)
	key := bytes.Repeat([]byte{4}, knockKeyLen)
	other := bytes.Repeat([]byte{5}, knockKeyLen)
	n := udptest.New()
	s := startServer(t, n, "203.0.113.10:0", Config{
		Clock:    testClock(),
		KnockKey: key,
	})
	c := newRawClient(t, n, "198.51.100.1", listenAddr(s))
	cid := randomID()
	c.knock = key
	cookie, ok := c.cookie(cid)
	a.True(ok, "a HELLO with the right key gets a COOKIE")

	c.knock = other
	_, ok = c.initFor(cid, cookie)
	a.False(ok, "an INIT with a bad mac1 gets no ACCEPT")
	a.Equal(uint64(1), s.Stats().KnockFail)
	a.Zero(s.pathCount())
}

func TestServerPendingPerSource(t *testing.T) {
	a := require.New(t)
	n := udptest.New()
	s := startServer(t, n, "203.0.113.10:0", Config{Clock: testClock()})
	c := newRawClient(t, n, "198.51.100.1", listenAddr(s))
	used := usedIDs{}
	for range 4 {
		c.establish(used.next())
	}
	cid := used.next()
	cookie, ok := c.cookie(cid)
	a.True(ok)
	_, ok = c.initFor(cid, cookie)
	a.False(ok, "the fifth pending INIT from one source is dropped")
	a.Equal(4, s.pathCount())
	a.Equal(uint64(1), s.Stats().PathsFull)
}

func TestServerInitRate(t *testing.T) {
	a := require.New(t)
	n := udptest.New()
	clk := testClock()
	s := startServer(t, n, "203.0.113.10:0", Config{
		Clock:  clk,
		Limits: Limits{MaxPendingPerSource: -1},
	})
	c := newRawClient(t, n, "198.51.100.1", listenAddr(s))
	used := usedIDs{}
	for range 8 {
		c.establish(used.next())
	}
	cid := used.next()
	cookie, ok := c.cookie(cid)
	a.True(ok)
	_, ok = c.initFor(cid, cookie)
	a.False(ok, "the ninth INIT within one second is dropped")
	a.Equal(uint64(1), s.Stats().RateLimited)

	clk.Advance(time.Second)
	for range 4 {
		c.establish(used.next())
	}
	a.Equal(12, s.pathCount(), "one second refills four tokens")
}

func TestServerPathsPerSource(t *testing.T) {
	a := require.New(t)
	n := udptest.New()
	s := startServer(t, n, "203.0.113.10:0", Config{
		Clock: testClock(),
		Limits: Limits{
			InitRate:            admit.Rate{PerSecond: 100, Burst: 100},
			MaxPendingPerSource: -1,
		},
	})
	c := newRawClient(t, n, "198.51.100.1", listenAddr(s))
	used := usedIDs{}
	for range 32 {
		c.establish(used.next())
	}
	cid := used.next()
	cookie, ok := c.cookie(cid)
	a.True(ok)
	_, ok = c.initFor(cid, cookie)
	a.False(ok, "the 33rd path from one source is dropped")
	a.Equal(32, s.pathCount())
	a.Equal(uint64(1), s.Stats().PathsFull)
}

func TestServerPathsPerNetwork(t *testing.T) {
	a := require.New(t)
	n := udptest.New()
	s := startServer(t, n, "203.0.113.10:0", Config{Clock: testClock()})
	used := usedIDs{}
	for i := 1; i <= 128; i++ {
		ip := fmt.Sprintf("198.51.100.%d", i)
		newRawClient(t, n, ip, listenAddr(s)).establish(used.next())
	}
	c := newRawClient(t, n, "198.51.100.200", listenAddr(s))
	cid := used.next()
	cookie, ok := c.cookie(cid)
	a.True(ok)
	_, ok = c.initFor(cid, cookie)
	a.False(ok, "the 129th path from one /24 is dropped")
	a.Equal(128, s.pathCount())

	other := newRawClient(t, n, "203.0.113.1", listenAddr(s))
	other.establish(used.next())
	a.Equal(129, s.pathCount(), "another network is not affected")
}

func TestServerPendingEvictsHalfOpenFirst(t *testing.T) {
	a := require.New(t)
	n := udptest.New()
	s := startServer(t, n, "203.0.113.10:0", Config{
		Clock:  testClock(),
		Limits: Limits{MaxPending: 3},
	})
	used := usedIDs{}
	// Network A holds a QUEUED path, then a HALF_OPEN one. Network B holds one
	// HALF_OPEN path, so A is the largest network.
	a1 := newRawClient(t, n, "198.51.100.1", listenAddr(s))
	queued := a1.establish(used.next())
	a1.data(queued, 1, []byte("q"))
	eventually(t, func() bool { return s.queuedCount() == 1 }, "no queue")
	a2 := newRawClient(t, n, "198.51.100.2", listenAddr(s))
	half := a2.establish(used.next())
	b := newRawClient(t, n, "203.0.113.1", listenAddr(s))
	bPath := b.establish(used.next())
	a.Equal(3, s.pathCount())

	d := newRawClient(t, n, "192.0.2.1", listenAddr(s))
	dPath := d.establish(used.next())

	a.Equal(2, a2.closes(half, 300*time.Millisecond),
		"the HALF_OPEN path of the largest network is evicted")
	a.Zero(a1.closes(queued, 200*time.Millisecond), "QUEUED stays")
	a.Zero(b.closes(bPath, 200*time.Millisecond))
	a.Equal(uint64(1), s.Stats().Evicted)
	a.NotZero(dPath.sid)
	a.Equal(3, s.pathCount())

	p := acceptWithin(t, s)
	a.Equal(queued.cid, p.Conv())
}

func TestServerPendingRefusesWhenNoNetworkHasTwo(t *testing.T) {
	a := require.New(t)
	n := udptest.New()
	s := startServer(t, n, "203.0.113.10:0", Config{
		Clock:  testClock(),
		Limits: Limits{MaxPending: 2},
	})
	used := usedIDs{}
	b := newRawClient(t, n, "203.0.113.1", listenAddr(s))
	bPath := b.establish(used.next())
	c := newRawClient(t, n, "198.51.100.1", listenAddr(s))
	cPath := c.establish(used.next())

	d := newRawClient(t, n, "192.0.2.1", listenAddr(s))
	cid := used.next()
	cookie, ok := d.cookie(cid)
	a.True(ok)
	_, ok = d.initFor(cid, cookie)
	a.False(ok, "every network holds one path, so the INIT is dropped")
	a.Equal(uint64(1), s.Stats().PathsFull)
	a.Zero(s.Stats().Evicted)
	a.Zero(b.closes(bPath, 200*time.Millisecond))
	a.Zero(c.closes(cPath, 200*time.Millisecond))
	a.Equal(2, s.pathCount())
}

func TestServerMaxPathsEvictsOldestOfLargest(t *testing.T) {
	a := require.New(t)
	n := udptest.New()
	s := startServer(t, n, "203.0.113.10:0", Config{
		Clock:  testClock(),
		Limits: Limits{MaxPaths: 3},
	})
	used := usedIDs{}

	// The oldest path of network A is ACCEPTED, and its client is a real Dial
	// on the same network as the second path of A.
	pcA, err := n.Listen("198.51.100.1:0")
	a.NoError(err)
	client, err := Dial(
		testCtx(t, 5*time.Second), pcA, listenAddr(s), Config{},
	)
	a.NoError(err)
	t.Cleanup(func() { _ = client.Close() })
	write(t, client, []byte("first"))
	client.Start()
	oldest := acceptWithin(t, s)
	oldest.Start()

	a2 := newRawClient(t, n, "198.51.100.2", listenAddr(s))
	a2Path := a2.establish(used.next())
	b := newRawClient(t, n, "203.0.113.1", listenAddr(s))
	bPath := b.establish(used.next())
	a.Equal(3, s.pathCount())

	d := newRawClient(t, n, "192.0.2.1", listenAddr(s))
	dPath := d.establish(used.next())

	res := readWithin(t, client)
	a.ErrorIs(res.err, ErrPathClosed, "the evicted client path ends")
	eventually(t, func() bool {
		return client.Stats().CloseReceived == 2
	}, "the evicted client did not get two CLOSEs")
	a.Equal(uint64(1), s.Stats().Evicted)
	a.Zero(a2.closes(a2Path, 200*time.Millisecond))
	a.Zero(b.closes(bPath, 200*time.Millisecond))
	a.NotZero(dPath.sid)
	a.Equal(3, s.pathCount())
}

func TestServerCapRefusalKeepsPaths(t *testing.T) {
	a := require.New(t)
	n := udptest.New()
	s := startServer(t, n, "203.0.113.10:0", Config{
		Clock:  testClock(),
		Limits: Limits{MaxPathsPerSource: 1},
	})
	client, err := Dial(
		testCtx(t, 5*time.Second), dialPC(t, n), listenAddr(s), Config{},
	)
	a.NoError(err)
	t.Cleanup(func() { _ = client.Close() })
	write(t, client, []byte("one"))
	client.Start()
	sp := acceptWithin(t, s)
	sp.Start()

	// A second INIT from the same address hits the per-source cap.
	again := newRawClient(t, n, "127.0.0.1", listenAddr(s))
	cid := randomID()
	cookie, ok := again.cookie(cid)
	a.True(ok)
	_, ok = again.initFor(cid, cookie)
	a.False(ok)
	a.Equal(uint64(1), s.Stats().PathsFull)

	write(t, client, []byte("two"))
	res := readWithin(t, sp)
	a.NoError(res.err)
	a.Equal([]byte("one"), res.data)
	res = readWithin(t, sp)
	a.NoError(res.err)
	a.Equal([]byte("two"), res.data)
	a.Zero(s.Stats().Evicted)
}

func TestServerExpiry(t *testing.T) {
	a := require.New(t)
	n := udptest.New()
	clk := testClock()
	s := startServer(t, n, "203.0.113.10:0", Config{Clock: clk})
	used := usedIDs{}
	h := newRawClient(t, n, "198.51.100.1", listenAddr(s))
	halfPath := h.establish(used.next())
	q := newRawClient(t, n, "198.51.100.2", listenAddr(s))
	queuedPath := q.establish(used.next())
	q.data(queuedPath, 1, []byte("q"))
	eventually(t, func() bool { return s.queuedCount() == 1 }, "no queue")
	a.Equal(2, s.pathCount())

	clk.Advance(HalfOpenTimeout - time.Second)
	s.sweep(clk.Now())
	a.Zero(s.Stats().Expired, "HALF_OPEN lives for 5 s")

	clk.Advance(time.Second + time.Millisecond)
	s.sweep(clk.Now())
	a.Equal(uint64(1), s.Stats().Expired)
	a.Equal(2, h.closes(halfPath, 300*time.Millisecond))
	a.Zero(q.closes(queuedPath, 100*time.Millisecond))

	clk.Advance(QueuedTimeout - HalfOpenTimeout - 2*time.Second)
	s.sweep(clk.Now())
	a.Equal(uint64(1), s.Stats().Expired, "QUEUED lives for 10 s")

	clk.Advance(2*time.Second + time.Millisecond)
	s.sweep(clk.Now())
	a.Equal(uint64(2), s.Stats().Expired)
	a.Equal(2, q.closes(queuedPath, 300*time.Millisecond))
	a.Zero(s.pathCount())
}

func TestServerAcceptNeverReturnsExpired(t *testing.T) {
	a := require.New(t)
	n := udptest.New()
	clk := testClock()
	s := startServer(t, n, "203.0.113.10:0", Config{Clock: clk})
	q := newRawClient(t, n, "198.51.100.1", listenAddr(s))
	queuedPath := q.establish(usedIDs{}.next())
	q.data(queuedPath, 1, []byte("late"))
	eventually(t, func() bool { return s.queuedCount() == 1 }, "no queue")

	clk.Advance(QueuedTimeout + time.Second)
	type result struct {
		p   *Path
		err error
	}
	ch := make(chan result, 1)
	go func() {
		p, err := s.Accept()
		ch <- result{p: p, err: err}
	}()
	eventually(t, func() bool {
		return s.Stats().Expired == 1
	}, "the queued path did not expire")
	a.NoError(s.Close())
	r := <-ch
	a.Nil(r.p, "Accept never returns an expired path")
	a.ErrorIs(r.err, ErrListenerClosed)
	a.Equal(2, q.closes(queuedPath, 300*time.Millisecond))
}

func TestServerTwoPathsOneAddress(t *testing.T) {
	a := require.New(t)
	n := udptest.New()
	s := startServer(t, n, "203.0.113.10:0", Config{Clock: testClock()})
	c := newRawClient(t, n, "198.51.100.1", listenAddr(s))
	used := usedIDs{}
	pa := c.establish(used.next())
	pb := c.establish(used.next())
	c.data(pa, 1, []byte("a1"))
	c.data(pb, 1, []byte("b1"))
	paths := pathsByConv(t, s, 2)
	sa, sb := paths[pa.cid], paths[pb.cid]
	a.NotNil(sa)
	a.NotNil(sb)
	sa.Start()
	sb.Start()

	res := readWithin(t, sa)
	a.Equal([]byte("a1"), res.data)
	res = readWithin(t, sb)
	a.Equal([]byte("b1"), res.data)

	write(t, sa, []byte("to a"))
	write(t, sb, []byte("to b"))
	got, ok := c.recv(pa, time.Second)
	a.True(ok)
	a.Equal([]byte("to a"), got)
	got, ok = c.recv(pb, time.Second)
	a.True(ok)
	a.Equal([]byte("to b"), got)

	// A's DATA reaches A only. One ReadFrom on B stays open for the rest of
	// the test.
	bRead := readAsync(sb)
	c.data(pa, 2, []byte("only a"))
	res = readWithin(t, sa)
	a.Equal([]byte("only a"), res.data)
	select {
	case r := <-bRead:
		a.FailNow("B read A's DATA", "%q", r.data)
	case <-time.After(200 * time.Millisecond):
	}

	// DATA sealed with A's keys but sent to B's sid is a bad tag.
	before := s.Stats().BadTag
	c.send(sealPacket(nil, pa.keys.c2s, typeData, pb.sid, 3, []byte("x")))
	eventually(t, func() bool {
		return s.Stats().BadTag == before+1
	}, "the forged DATA was not rejected")

	// Closing A leaves B working.
	a.NoError(sa.Close())
	a.Equal(2, c.closes(pa, 300*time.Millisecond))
	c.data(pb, 2, []byte("b2"))
	select {
	case r := <-bRead:
		a.NoError(r.err)
		a.Equal([]byte("b2"), r.data)
	case <-time.After(time.Second):
		a.FailNow("B did not read its DATA after A closed")
	}
}

// TestServerRejectsOtherServersCookie checks that a cookie is bound to the
// secret of the server that issued it, so a restarted server refuses it.
func TestServerRejectsOtherServersCookie(t *testing.T) {
	a := require.New(t)
	n := udptest.New()
	clk := testClock()
	old := startServer(t, n, "203.0.113.10:0", Config{Clock: clk})
	fresh := startServer(t, n, "203.0.113.11:0", Config{Clock: clk})
	c := newRawClient(t, n, "198.51.100.1", listenAddr(old))
	cid := randomID()
	cookie, ok := c.cookie(cid)
	a.True(ok)

	c.server = listenAddr(fresh)
	_, ok = c.initFor(cid, cookie)
	a.False(ok, "the new server refuses the old server's cookie")
	a.Equal(uint64(1), fresh.Stats().BadCookie)
	a.Zero(fresh.pathCount())
}

// TestServerReplayedCloseAfterNewPath checks that a CLOSE of an ended path,
// replayed once a new path exists from the same address, ends nothing: it
// names the old sid.
func TestServerReplayedCloseAfterNewPath(t *testing.T) {
	a := require.New(t)
	n := udptest.New()
	s := startServer(t, n, "203.0.113.10:0", Config{Clock: testClock()})
	c := newRawClient(t, n, "198.51.100.1", listenAddr(s))
	used := usedIDs{}

	first := c.establish(used.next())
	closePkt := sealPacket(nil, first.keys.c2s, typeClose, first.sid, 1, nil)
	c.send(closePkt)
	eventually(t, func() bool { return s.pathCount() == 0 }, "CLOSE ignored")
	a.Equal(uint64(1), s.Stats().CloseReceived)

	second := c.establish(used.next())
	before := s.Stats().NoPath
	c.send(closePkt)
	eventually(t, func() bool {
		return s.Stats().NoPath == before+1
	}, "the replayed CLOSE was not dropped")
	a.Equal(1, s.pathCount())
	a.Equal(uint64(1), s.Stats().CloseReceived)

	c.data(second, 1, []byte("alive"))
	sp := acceptWithin(t, s)
	a.Equal(second.cid, sp.Conv())
	sp.Start()
	res := readWithin(t, sp)
	a.NoError(res.err)
	a.Equal([]byte("alive"), res.data)
}

func TestServerCloseEndsPendingPaths(t *testing.T) {
	a := require.New(t)
	n := udptest.New()
	before := runtime.NumGoroutine()
	pc, err := n.Listen("203.0.113.10:0")
	a.NoError(err)
	s, err := NewServer(pc, Config{Clock: testClock()})
	a.NoError(err)
	used := usedIDs{}
	c := newRawClient(t, n, "198.51.100.1", listenAddr(s))
	half := c.establish(used.next())
	q := newRawClient(t, n, "198.51.100.2", listenAddr(s))
	queued := q.establish(used.next())
	q.data(queued, 1, []byte("q"))
	eventually(t, func() bool { return s.pathCount() == 2 }, "no paths")

	a.NoError(s.Close())
	a.Equal(2, c.closes(half, 300*time.Millisecond))
	a.Equal(2, q.closes(queued, 300*time.Millisecond))
	a.Zero(s.pathCount())
	eventually(t, func() bool {
		return runtime.NumGoroutine() <= before
	}, fmt.Sprintf("goroutines did not return to %d", before))
}

func TestServerCloseKeepsAcceptedPath(t *testing.T) {
	a := require.New(t)
	n := udptest.New()
	addr := "203.0.113.10:7000"
	s := startServer(t, n, addr, Config{Clock: testClock()})
	c := newRawClient(t, n, "198.51.100.1", listenAddr(s))
	rp := c.establish(usedIDs{}.next())
	c.data(rp, 1, []byte("hi"))
	sp := acceptWithin(t, s)
	sp.Start()
	res := readWithin(t, sp)
	a.Equal([]byte("hi"), res.data)

	a.NoError(s.Close())
	write(t, sp, []byte("still"))
	got, ok := c.recv(rp, time.Second)
	a.True(ok)
	a.Equal([]byte("still"), got)
	c.data(rp, 2, []byte("in"))
	res = readWithin(t, sp)
	a.Equal([]byte("in"), res.data)

	_, err := s.Accept()
	a.ErrorIs(err, ErrListenerClosed)
	fresh := newRawClient(t, n, "198.51.100.9", listenAddr(s))
	a.Zero(countType(fresh.dropHello(randomID()), typeCookie),
		"a closing server answers no HELLO")

	_, err = n.Listen(addr)
	a.Error(err, "the port stays bound while the path lives")
	a.NoError(sp.Close())
	pc, err := n.Listen(addr)
	a.NoError(err, "the port is free once the last path ends")
	_ = pc.Close()
	a.Equal(2, c.closes(rp, 300*time.Millisecond))
}

func TestServerAmplificationInvariant(t *testing.T) {
	a := require.New(t)
	n := udptest.New()
	s := startServer(t, n, "203.0.113.10:7000", Config{Clock: testClock()})
	srv := listenAddr(s)

	var mu sync.Mutex
	in := make(map[netip.AddrPort]int)
	out := make(map[netip.AddrPort]int)
	n.SetFilter(func(from, to netip.AddrPort, pkt []byte) int {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case to == srv:
			in[from] += len(pkt)
		case from == srv:
			out[to] += len(pkt)
		}
		return 1
	})

	rng := rand.New(rand.NewPCG(1, 2))
	for range 3000 {
		src := netip.AddrPortFrom(
			netip.AddrFrom4([4]byte{
				10, byte(rng.IntN(256)), byte(rng.IntN(256)),
				byte(rng.IntN(256)),
			}),
			uint16(1024+rng.IntN(60000)),
		)
		n.Inject(src, srv, randomDatagram(rng))
	}

	// The worker answers HELLOs in order, so the COOKIE of this sentinel shows
	// that it has answered every packet queued before it.
	sentinel := newRawClient(t, n, "198.51.100.1", srv)
	cid := randomID()
	eventually(t, func() bool {
		sentinel.send(encodeHello(cid, nil))
		_, ok := sentinel.await(20*time.Millisecond, func(p []byte) bool {
			m, err := parseCookie(p)
			return err == nil && m.cid == cid
		})
		return ok
	}, "the sentinel HELLO got no COOKIE")

	mu.Lock()
	defer mu.Unlock()
	a.NotEmpty(out)
	for src, sent := range out {
		a.LessOrEqual(sent, in[src], "bytes sent to %v", src)
	}
	st := s.Stats()
	a.Positive(st.Hello)
	a.Positive(st.BadCookie)
	a.Zero(s.pathCount(), "no path without a valid cookie and an ACCEPT")
}

// randomDatagram returns a hostile datagram of one of several shapes: garbage,
// HELLOs, INITs with random cookies, DATA and CLOSE with random ids, and
// oversize datagrams.
func randomDatagram(rng *rand.Rand) []byte {
	randomBytes := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(rng.Uint32())
		}
		return b
	}
	nonzero := func() uint32 { return rng.Uint32() | 1 }
	switch rng.IntN(6) {
	case 0:
		return randomBytes(rng.IntN(1500))
	case 1:
		return encodeHello(nonzero(), nil)
	case 2:
		var cookie [cookieLen]byte
		copy(cookie[:], randomBytes(cookieLen))
		return encodeInit(nonzero(), cookie, randomBytes(ephLen), nil)
	case 3:
		b := randomBytes(1201 + rng.IntN(60000))
		b[0], b[1], b[2], b[3] = typeHello, Version, 0, 0
		return b
	case 4:
		b := randomBytes(DataOverhead + 1 + rng.IntN(KCPMTU))
		putHeader(b, typeData)
		binary.BigEndian.PutUint32(b[4:], nonzero())
		return b
	default:
		b := randomBytes(CloseSize)
		putHeader(b, typeClose)
		binary.BigEndian.PutUint32(b[4:], nonzero())
		return b
	}
}

func TestServerConcurrentPaths(t *testing.T) {
	a := require.New(t)
	n := udptest.New()
	s := startServer(t, n, "203.0.113.10:0", Config{Clock: testClock()})
	const count, msgs = 8, 20

	clients := make([]*Path, count)
	dialErrs := make(chan error, count)
	var dials sync.WaitGroup
	for i := range count {
		pc, err := n.Listen(fmt.Sprintf("198.51.100.%d:0", 10+i))
		a.NoError(err)
		dials.Go(func() {
			ctx, cancel := context.WithTimeout(
				context.Background(), 5*time.Second,
			)
			defer cancel()
			p, err := Dial(ctx, pc, listenAddr(s), Config{})
			if err != nil {
				dialErrs <- err
				return
			}
			clients[i] = p
		})
	}
	dials.Wait()
	close(dialErrs)
	for err := range dialErrs {
		a.NoError(err)
	}
	for _, c := range clients {
		t.Cleanup(func() { _ = c.Close() })
		write(t, c, []byte("hello"))
		c.Start()
	}
	servers := pathsByConv(t, s, count)

	// Each server path first reads the "hello" its client sent.
	for _, c := range clients {
		sp := servers[c.Conv()]
		a.NotNil(sp, "no server path for a client")
		sp.Start()
		res := readWithin(t, sp)
		a.Equal([]byte("hello"), res.data)
	}

	failures := make(chan error, count*(2*msgs+2))
	var wg sync.WaitGroup
	for _, c := range clients {
		sp := servers[c.Conv()]
		wg.Add(4)
		go func() {
			defer wg.Done()
			for k := range msgs {
				_, err := c.WriteTo(fmt.Appendf(nil, "c%d", k), nil)
				if err != nil {
					failures <- err
				}
			}
		}()
		go func() {
			defer wg.Done()
			for k := range msgs {
				_, err := sp.WriteTo(fmt.Appendf(nil, "s%d", k), nil)
				if err != nil {
					failures <- err
				}
			}
		}()
		go func() {
			defer wg.Done()
			failures <- expectInOrder(sp, "c", msgs)
		}()
		go func() {
			defer wg.Done()
			failures <- expectInOrder(c, "s", msgs)
		}()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		a.NoError(err)
	}
}

// expectInOrder reads n messages from p, which must read prefix0 to prefixN-1
// in order. It returns the first one that differs, or that does not arrive
// within two seconds.
func expectInOrder(p *Path, prefix string, n int) error {
	buf := make([]byte, KCPMTU)
	for k := range n {
		want := fmt.Sprintf("%s%d", prefix, k)
		ch := make(chan error, 1)
		go func() {
			m, _, err := p.ReadFrom(buf)
			if err == nil && string(buf[:m]) != want {
				err = fmt.Errorf("got %q, want %q", buf[:m], want)
			}
			ch <- err
		}()
		select {
		case err := <-ch:
			if err != nil {
				return err
			}
		case <-time.After(2 * time.Second):
			return errors.New("message did not arrive")
		}
	}
	return nil
}

func TestServerHandshakeQueueFull(t *testing.T) {
	a := require.New(t)
	n := udptest.New()
	release := make(chan struct{})
	s := startServer(t, n, "203.0.113.10:7000", Config{
		Clock: testClock(),
		// Allow blocks the worker until the test releases it.
		Allow: func(netip.AddrPort) bool {
			<-release
			return true
		},
	})
	defer close(release)

	// The worker holds at most one packet while it is blocked, so at most
	// HandshakeQueue+1 of these fit, and the rest are dropped.
	const sent = HandshakeQueue + 44
	src := netip.MustParseAddrPort("198.51.100.1:4000")
	for range sent {
		s.enqueue(src, encodeHello(randomID(), nil))
	}
	a.GreaterOrEqual(s.Stats().HandshakeDropped, uint64(sent-HandshakeQueue-1))
}

func BenchmarkDataUnderHelloFlood(b *testing.B) {
	a := require.New(b)
	n := udptest.New()
	s := startServer(b, n, "203.0.113.10:7000", Config{})
	srv := listenAddr(s)
	pc, err := n.Listen("198.51.100.1:0")
	a.NoError(err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := Dial(ctx, pc, srv, Config{})
	a.NoError(err)
	b.Cleanup(func() { _ = client.Close() })
	_, err = client.WriteTo([]byte("hi"), nil)
	a.NoError(err)
	client.Start()
	sp, err := s.Accept()
	a.NoError(err)
	sp.Start()

	go func() {
		buf := make([]byte, KCPMTU)
		for {
			m, _, err := sp.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = sp.WriteTo(buf[:m], nil)
		}
	}()
	replies := make(chan uint64, 1024)
	go func() {
		buf := make([]byte, KCPMTU)
		for {
			m, _, err := client.ReadFrom(buf)
			if err != nil {
				return
			}
			if m == 8 {
				replies <- binary.BigEndian.Uint64(buf[:8])
			}
		}
	}()

	stop := make(chan struct{})
	var flood sync.WaitGroup
	flood.Go(func() {
		rng := rand.New(rand.NewPCG(9, 10))
		for {
			select {
			case <-stop:
				return
			default:
			}
			src := netip.AddrPortFrom(
				netip.AddrFrom4([4]byte{
					10, byte(rng.IntN(256)), byte(rng.IntN(256)),
					byte(rng.IntN(256)),
				}),
				uint16(1024+rng.IntN(60000)),
			)
			n.Inject(src, srv, encodeHello(randomID(), nil))
		}
	})
	defer func() {
		close(stop)
		flood.Wait()
	}()

	payload := make([]byte, 8)
	var seq uint64
	for b.Loop() {
		seq++
		binary.BigEndian.PutUint64(payload, seq)
		for {
			if _, err := client.WriteTo(payload, nil); err != nil {
				b.Fatal(err)
			}
			if awaitReply(replies, seq, 50*time.Millisecond) {
				break
			}
		}
	}
}

// awaitReply reports whether seq arrives on replies within d. Replies with
// other sequence numbers are skipped.
func awaitReply(replies <-chan uint64, seq uint64, d time.Duration) bool {
	deadline := time.After(d)
	for {
		select {
		case got := <-replies:
			if got == seq {
				return true
			}
		case <-deadline:
			return false
		}
	}
}
