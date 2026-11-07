package kamune

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/internal/udppath"
	"github.com/kamune-org/kamune/internal/udppath/udptest"
	"github.com/kamune-org/kamune/pkg/storage"
)

// udpAttackBurst is how many datagrams the end-to-end attacker writes
// before it forwards only captured DATA. A few hundred keeps the test light.
const udpAttackBurst = 240

// udpAttackPace is the gap between those datagrams.
const udpAttackPace = 2 * time.Millisecond

// exhaustionSources is RFC008 §14.3's 64 sources, scaled down by 8.
// exhaustionPerSource stays 32, so the server holds 256 accepted paths.
const (
	exhaustionSources   = 8
	exhaustionPerSource = 32
	exhaustionPaths     = exhaustionSources * exhaustionPerSource

	// exhaustionGap is the pause between two dials from one source.
	// The path layer allows 4 INITs a second per source after a burst of 8,
	// and 4 pending paths per source. A new dial starts only after this gap,
	// so neither cap refuses a path while the 256 are filling.
	exhaustionGap = 300 * time.Millisecond
)

// validHello is a 1200-byte HELLO for cid with no knock. Bytes after the
// header are zero, which is the padding parseHello requires.
func validHello(cid uint32) []byte {
	b := make([]byte, udppath.HelloSize)
	b[0] = udpTypeHello
	b[1] = udppath.Version
	binary.BigEndian.PutUint32(b[4:], cid)
	return b
}

// udpJunk is a short datagram in the path layer's type range. Its length
// matches no packet, so the server counts it as malformed.
func udpJunk() []byte {
	b := make([]byte, 32)
	b[0] = 0x09
	for i := 1; i < len(b); i++ {
		b[i] = 0xff
	}
	return b
}

// udpOversize is a DATA-typed datagram larger than the path layer accepts.
// 9,000 bytes is under the 9,216-byte UDP cap macOS uses by default.
func udpOversize() []byte {
	b := make([]byte, 9000)
	b[0] = udpTypeData
	return b
}

// unmapAddr drops an IPv4-in-IPv6 mapping. The path layer stores peers that way.
func unmapAddr(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// addrIn reports whether ap is in set, ignoring IPv4-in-IPv6 mapping.
func addrIn(ap netip.AddrPort, set []netip.AddrPort) bool {
	ap = unmapAddr(ap)
	for _, s := range set {
		if unmapAddr(s) == ap {
			return true
		}
	}
	return false
}

// loopbackUDP listens on 127.0.0.1 and an ephemeral port. The caller closes it.
func loopbackUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	_ = c.SetReadBuffer(4 << 20)
	_ = c.SetWriteBuffer(4 << 20)
	return c
}

// udpRelay is the forwarder between dialers and the server. Dialers dial
// listen. Each dialer source gets one socket toward the server, and that
// socket is the path address the server sees. DATA sent toward the server
// is written a second time, and one copy is offered on captured.
type udpRelay struct {
	listen   *net.UDPConn
	server   *net.UDPAddr
	captured chan []byte

	mu      sync.Mutex
	byPeer  map[netip.AddrPort]*net.UDPConn
	conns   []*net.UDPConn
	remotes []netip.AddrPort
	err     error
	stopped bool
	once    sync.Once
	wg      sync.WaitGroup
}

// newUDPRelay listens on 127.0.0.1 and relays to server.
// captured receives DATA copies when the send does not block.
func newUDPRelay(
	t *testing.T, server *net.UDPAddr, captured chan []byte,
) *udpRelay {
	t.Helper()
	ln := loopbackUDP(t)
	f := &udpRelay{
		listen:   ln,
		server:   server,
		captured: captured,
		byPeer:   make(map[netip.AddrPort]*net.UDPConn),
	}
	f.wg.Add(1)
	go f.readDialers()
	return f
}

// addr is the address dialers dial.
func (f *udpRelay) addr() string { return f.listen.LocalAddr().String() }

// pathRemotes returns the addresses of the sockets that face the server.
func (f *udpRelay) pathRemotes() []netip.AddrPort {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]netip.AddrPort(nil), f.remotes...)
}

// dialErr returns the first error from opening a socket toward the server.
func (f *udpRelay) dialErr() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.err
}

// stop closes every socket and waits for the relay's goroutines.
func (f *udpRelay) stop() {
	f.once.Do(func() {
		f.mu.Lock()
		f.stopped = true
		conns := append([]*net.UDPConn(nil), f.conns...)
		f.mu.Unlock()
		_ = f.listen.Close()
		for _, c := range conns {
			_ = c.Close()
		}
		f.wg.Wait()
	})
}

func (f *udpRelay) readDialers() {
	defer f.wg.Done()
	buf := make([]byte, 65536)
	for {
		n, from, err := f.listen.ReadFromUDP(buf)
		if err != nil || from == nil {
			return
		}
		pkt := bytes.Clone(buf[:n])
		tw := f.toward(from)
		if tw == nil {
			return
		}
		_, _ = tw.WriteTo(pkt, f.server)
		if len(pkt) > 0 && pkt[0] == udpTypeData {
			_, _ = tw.WriteTo(pkt, f.server)
			select {
			case f.captured <- pkt:
			default:
			}
		}
	}
}

// toward returns the server-facing socket for the dialer at from,
// opening one when this is the dialer's first datagram.
func (f *udpRelay) toward(from *net.UDPAddr) *net.UDPConn {
	key := unmapAddr(from.AddrPort())
	reply := net.UDPAddrFromAddrPort(key)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stopped {
		return nil
	}
	if c, ok := f.byPeer[key]; ok {
		return c
	}
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		if f.err == nil {
			f.err = err
		}
		return nil
	}
	_ = c.SetReadBuffer(4 << 20)
	_ = c.SetWriteBuffer(4 << 20)
	f.byPeer[key] = c
	f.conns = append(f.conns, c)
	f.remotes = append(f.remotes, unmapAddr(
		c.LocalAddr().(*net.UDPAddr).AddrPort(),
	))
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		f.copyToDialer(c, reply)
	}()
	return c
}

// copyToDialer writes what the server sends back to one dialer,
// from the listen socket, so the dialer sees the address it dialed.
func (f *udpRelay) copyToDialer(conn *net.UDPConn, dialer *net.UDPAddr) {
	buf := make([]byte, 65536)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = f.listen.WriteTo(buf[:n], dialer)
	}
}

// udpAttack sends HELLOs, junk, raw KCP, oversize datagrams and captured
// DATA to dst, and records the size of every reply.
type udpAttack struct {
	conn *net.UDPConn
	dst  *net.UDPAddr
	caps <-chan []byte
	done chan struct{}

	mu       sync.Mutex
	sizes    []int
	sent     int
	recv     int
	writeErr error
	stopping atomic.Bool
	once     sync.Once
	wg       sync.WaitGroup
}

// newUDPAttack listens on 127.0.0.1 and starts sending to dst.
func newUDPAttack(
	t *testing.T, dst *net.UDPAddr, caps <-chan []byte,
) *udpAttack {
	t.Helper()
	a := &udpAttack{
		conn: loopbackUDP(t),
		dst:  dst,
		caps: caps,
		done: make(chan struct{}),
	}
	a.wg.Add(2)
	go a.send()
	go a.read()
	return a
}

// stop tells the sender to exit, drains replies for a short bound,
// and waits for both goroutines.
func (a *udpAttack) stop() {
	a.once.Do(func() {
		a.stopping.Store(true)
		close(a.done)
		_ = a.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		a.wg.Wait()
		_ = a.conn.Close()
	})
}

// local is the attacker's own address.
func (a *udpAttack) local() netip.AddrPort {
	return unmapAddr(a.conn.LocalAddr().(*net.UDPAddr).AddrPort())
}

// account returns replies, their sizes, bytes received and bytes sent.
func (a *udpAttack) account() (sizes []int, recvN, sentN int, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]int(nil), a.sizes...), a.recv, a.sent, a.writeErr
}

func (a *udpAttack) send() {
	defer a.wg.Done()
	junk := udpJunk()
	over := udpOversize()
	kcp := kcpSegment(foreignConv, kcpPushCmd, []byte{0x01})
	var id uint32 = 1
	for sentN := 0; sentN < udpAttackBurst; sentN++ {
		if !a.alive() {
			return
		}
		var pkt []byte
		select {
		case pkt = <-a.caps:
		default:
			switch sentN % 4 {
			case 0:
				pkt = validHello(id)
				id++
			case 1:
				pkt = junk
			case 2:
				pkt = kcp
			default:
				pkt = over
			}
		}
		if !a.write(pkt) || !a.pause(udpAttackPace) {
			return
		}
	}
	for {
		select {
		case <-a.done:
			return
		case pkt := <-a.caps:
			if !a.write(pkt) {
				return
			}
		}
	}
}

func (a *udpAttack) alive() bool {
	select {
	case <-a.done:
		return false
	default:
		return true
	}
}

func (a *udpAttack) pause(d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-a.done:
		return false
	case <-timer.C:
		return true
	}
}

func (a *udpAttack) write(pkt []byte) bool {
	n, err := a.conn.WriteTo(pkt, a.dst)
	if err != nil {
		if !a.stopping.Load() {
			a.mu.Lock()
			if a.writeErr == nil {
				a.writeErr = err
			}
			a.mu.Unlock()
		}
		return false
	}
	a.mu.Lock()
	a.sent += n
	a.mu.Unlock()
	return true
}

func (a *udpAttack) read() {
	defer a.wg.Done()
	buf := make([]byte, 65536)
	for {
		n, _, err := a.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		a.mu.Lock()
		a.sizes = append(a.sizes, n)
		a.recv += n
		a.mu.Unlock()
	}
}

// verifyLog records every verifier call and stores the peer, which a later
// resume needs FindPeer to see.
type verifyLog struct {
	mu    sync.Mutex
	calls []VerifyRequest
}

func (l *verifyLog) verify(
	_ context.Context, st *storage.Storage, req VerifyRequest,
) error {
	if err := st.StorePeer(req.Peer); err != nil {
		return err
	}
	l.mu.Lock()
	l.calls = append(l.calls, req)
	l.mu.Unlock()
	return nil
}

// sawResponder reports whether the server verifier ran with Resumed equal
// to resumed. The dialer's own verifier call leaves Resumed false.
func (l *verifyLog) sawResponder(resumed bool) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.calls {
		if c.Role == RoleResponder && c.Resumed == resumed {
			return true
		}
	}
	return false
}

// TestUDPEndToEnd is RFC008 §14.4. A dialer reaches a real loopback server
// through a forwarder that duplicates DATA, while an attacker writes at the
// server's socket.
func TestUDPEndToEnd(t *testing.T) {
	a := require.New(t)
	serverStore, cleanupServer := newTestStore(t)
	t.Cleanup(cleanupServer)
	clientStore, cleanupClient := newTestStore(t)
	t.Cleanup(cleanupClient)

	hold := make(chan struct{})
	var holdOnce sync.Once
	releaseHold := func() { holdOnce.Do(func() { close(hold) }) }
	sessions := make(chan *Transport, 4)
	var (
		live    []*Transport
		handled []*Transport
	)
	log := &verifyLog{}
	server, err := NewServer(
		"127.0.0.1:0",
		func(tr *Transport) error {
			sessions <- tr
			<-hold
			return nil
		},
		serverStore,
		log.verify,
		ServeWithUDP(),
	)
	a.NoError(err)
	go func() { _ = server.ListenAndServe() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), udpTimeout)
		defer cancel()
		_ = server.Shutdown(ctx)
	})

	pl, ok := server.listener.(*pathListener)
	a.True(ok)
	ua, ok := pl.srv.Addr().(*net.UDPAddr)
	a.True(ok)
	serverAddr := net.UDPAddrFromAddrPort(unmapAddr(ua.AddrPort()))
	before := pl.srv.Stats()

	captured := make(chan []byte, 64)
	relay := newUDPRelay(t, serverAddr, captured)
	attack := newUDPAttack(t, serverAddr, captured)
	t.Cleanup(func() {
		attack.stop()
		relay.stop()
		for _, tr := range live {
			_ = tr.CloseAbort()
		}
		releaseHold()
	})

	// 1. Cold handshake. The rate limit stays on: two handshakes from
	// 127.0.0.1 are inside the defaults.
	dialer, err := NewDialer(
		relay.addr(), clientStore, log.verify, DialWithUDP(),
	)
	a.NoError(err)
	cli, err := dialer.Dial()
	a.NoError(err, "relay: %v stats: %+v", relay.dialErr(), pl.srv.Stats())
	a.False(cli.Resumed())
	srv := recv(t, sessions)
	live = append(live, cli, srv)
	handled = append(handled, srv)
	a.True(log.sawResponder(false), "verifier did not run")

	// 2. One hundred messages each way.
	for i := range 100 {
		sendRecv(t, cli, srv, []byte{'c', byte(i)})
		sendRecv(t, srv, cli, []byte{'s', byte(i)})
	}

	// 3. Ping, then pong. The test drives the transport the handler handed
	// over, which is the server side of the session.
	a.NoError(srv.SetDeadline(time.Now().Add(udpTimeout)))
	_, err = cli.Send(Bytes([]byte("ping")), RoutePing)
	a.NoError(err)
	ping := Bytes(nil)
	md, err := srv.Receive(ping)
	a.NoError(err)
	a.Equal(RoutePing, md.Route())
	a.Equal([]byte("ping"), ping.Value)
	a.NoError(cli.SetDeadline(time.Now().Add(udpTimeout)))
	_, err = srv.Send(Bytes([]byte("pong")), RoutePong)
	a.NoError(err)
	pong := Bytes(nil)
	md, err = cli.Receive(pong)
	a.NoError(err)
	a.Equal(RoutePong, md.Route())
	a.Equal([]byte("pong"), pong.Value)

	// Transport.Close deletes the resumption row, and the server's Receive
	// of RouteCloseTransport deletes its row too, so a resume after that
	// close cannot succeed. The cold session is dropped with CloseAbort,
	// which keeps both rows. The graceful close is checked on the resumed
	// session, after the resume has been observed.
	sessionID := cli.SessionID()
	a.NoError(cli.CloseAbort())
	a.NoError(srv.CloseAbort())

	// 5. Resume over a new path through the forwarder.
	again, err := NewDialer(
		relay.addr(), clientStore, log.verify,
		DialWithUDP(), DialWithResume(sessionID),
	)
	a.NoError(err)
	cli2, err := again.Dial()
	a.NoError(err, "relay: %v stats: %+v", relay.dialErr(), pl.srv.Stats())
	a.True(cli2.Resumed())
	a.Equal(sessionID, cli2.SessionID())
	srv2 := recv(t, sessions)
	live = append(live, cli2, srv2)
	handled = append(handled, srv2)
	a.True(log.sawResponder(true), "verifier did not see the resume")
	sendRecv(t, cli2, srv2, []byte("after resume"))

	// 4. Graceful close, on the resumed session. Lossless loopback, so the
	// server's Receive is the peer's close and not a dropped connection.
	a.NoError(srv2.SetDeadline(time.Now().Add(udpTimeout)))
	closed := make(chan error, 1)
	go func() {
		_, rerr := srv2.Receive(Bytes(nil))
		closed <- rerr
	}()
	a.NoError(cli2.Close())
	a.ErrorIs(recv(t, closed), ErrPeerDisconnected)

	a.Eventually(func() bool {
		st := pl.srv.Stats()
		return st.Replay > before.Replay &&
			st.NoPath > before.NoPath &&
			st.Malformed > before.Malformed &&
			st.Foreign > before.Foreign
	}, udpTimeout, 20*time.Millisecond, "stats: %+v", pl.srv.Stats())
	attack.stop()
	sizes, recvN, sentN, werr := attack.account()
	a.NoError(werr)
	a.NotEmpty(sizes, "the attacker got no reply")
	a.LessOrEqual(recvN, sentN)
	for _, n := range sizes {
		a.LessOrEqual(n, udppath.CookieSize)
	}

	remotes := relay.pathRemotes()
	a.NotEmpty(remotes)
	a.Len(handled, 2)
	for _, tr := range handled {
		got := remoteOf(tr)
		a.True(addrIn(got, remotes),
			"remote %s, forwarder %v", got, remotes)
		a.NotEqual(attack.local(), unmapAddr(got))
	}
	select {
	case extra := <-sessions:
		t.Fatalf("handler got an extra session from %s", remoteOf(extra))
	default:
	}
}

// pathDialCtx dials the path layer from pc. The dial stops when ctx ends.
// The caller still owns pc when the dial fails.
func pathDialCtx(ctx context.Context, pc net.PacketConn) DialOption {
	return DialWithFunc(func(addr string) (Conn, error) {
		ap, err := netip.ParseAddrPort(addr)
		if err != nil {
			return nil, err
		}
		dctx, cancel := context.WithTimeout(ctx, udpTimeout)
		defer cancel()
		return DialUDP(dctx, pc, ap)
	})
}

// TestUDPExhaustionFromManySources is RFC008 §14.3 scaled down by 8.
// 2,048 accepted kamune sessions would take gigabytes under the race
// detector. 8 sources in 8 /24s hold 32 paths each, 256 in all.
func TestUDPExhaustionFromManySources(t *testing.T) {
	if testing.Short() {
		t.Skip("holds 256 kamune handshakes")
	}
	a := require.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	n := udptest.New()
	pc, err := n.Listen("10.255.0.1:1")
	a.NoError(err)
	l, err := ListenUDP(pc, UDPWithPathLimits(UDPPathLimits{MaxPaths: 256}))
	a.NoError(err)
	serverAddr := udpAddrPort(pc).String()

	// 32 handshakes from one source would pass the kamune per-source cap
	// of 16 (defaultMaxPendingPerSource) and the default source rate
	// (burst 16). Both are off. The path layer's MaxPaths is what fills.
	serverStore, cleanupServer := newTestStore(t)
	t.Cleanup(cleanupServer)
	realStore, cleanupReal := newTestStore(t)
	t.Cleanup(cleanupReal)
	realPub, err := realStore.PublicKey()
	a.NoError(err)
	realPub = bytes.Clone(realPub)

	release := make(chan struct{})
	var releaseOnce sync.Once
	letGo := func() { releaseOnce.Do(func() { close(release) }) }
	var entered atomic.Int32
	hold := make(chan struct{})
	var holdOnce sync.Once
	releaseHold := func() { holdOnce.Do(func() { close(hold) }) }
	sessions := make(chan *Transport, 1)

	server, err := NewServer(
		"",
		func(tr *Transport) error {
			sessions <- tr
			<-hold
			return nil
		},
		serverStore,
		func(
			vctx context.Context, st *storage.Storage, req VerifyRequest,
		) error {
			if bytes.Equal(req.Peer.PublicKey, realPub) {
				return st.StorePeer(req.Peer)
			}
			entered.Add(1)
			select {
			case <-vctx.Done():
				return vctx.Err()
			case <-release:
				if err := vctx.Err(); err != nil {
					return err
				}
				return nil
			}
		},
		ServeWithListener(l),
		ServeWithHandshakeRate(RateLimit{}, RateLimit{}, RateLimit{}),
		ServeWithMaxPendingPerSource(0),
	)
	a.NoError(err)
	go func() { _ = server.ListenAndServe() }()
	t.Cleanup(func() {
		shut, stop := context.WithTimeout(context.Background(), udpTimeout)
		defer stop()
		_ = server.Shutdown(shut)
	})

	type src struct {
		store *storage.Storage
		ip    netip.Addr
	}
	sources := make([]src, exhaustionSources)
	for i := range sources {
		st, cleanup := newTestStore(t)
		t.Cleanup(cleanup)
		_, err = st.PublicKey()
		a.NoError(err)
		sources[i] = src{
			store: st,
			ip:    netip.AddrFrom4([4]byte{10, 0, byte(i), 1}),
		}
	}

	errc := make(chan error, exhaustionPaths)
	var pacers, dials sync.WaitGroup
	var started atomic.Int32
	for i := range sources {
		pacers.Add(1)
		go func(i int) {
			defer pacers.Done()
			for j := range exhaustionPerSource {
				if ctx.Err() != nil {
					return
				}
				dials.Add(1)
				started.Add(1)
				go func() {
					defer dials.Done()
					sock, lerr := n.Listen(net.JoinHostPort(
						sources[i].ip.String(), "0",
					))
					if lerr != nil {
						select {
						case errc <- lerr:
						default:
						}
						return
					}
					defer func() { _ = sock.Close() }()
					d, derr := NewDialer(
						serverAddr, sources[i].store, allowAll,
						pathDialCtx(ctx, sock),
					)
					if derr != nil {
						select {
						case errc <- derr:
						default:
						}
						return
					}
					tr, derr := d.DialContext(ctx)
					if tr != nil {
						_ = tr.CloseAbort()
					}
					select {
					case errc <- derr:
					default:
					}
				}()
				if j+1 == exhaustionPerSource {
					return
				}
				timer := time.NewTimer(exhaustionGap)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}
		}(i)
	}
	// Cancel runs before Wait: cleanups run last-added first, and the
	// deferred cancel above runs before either of them.
	t.Cleanup(func() {
		pacers.Wait()
		dials.Wait()
	})
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
		letGo()
		releaseHold()
	})

	deadline := time.NewTimer(45 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for int(entered.Load()) < exhaustionPaths {
		select {
		case err := <-errc:
			t.Fatalf(
				"attacker dial: %v; entered %d started %d stats %+v",
				err, entered.Load(), started.Load(),
				l.(*pathListener).srv.Stats(),
			)
		case <-deadline.C:
			t.Fatalf(
				"attackers: entered %d started %d stats %+v",
				entered.Load(), started.Load(),
				l.(*pathListener).srv.Stats(),
			)
		case <-tick.C:
		}
	}
	a.Equal(int32(exhaustionPaths), entered.Load())

	before := l.(*pathListener).srv.Stats()
	a.Zero(before.Evicted)
	realPC, err := n.Listen("10.0.8.1:1")
	a.NoError(err)
	t.Cleanup(func() { _ = realPC.Close() })
	real, err := udpDialer(t, realStore, realPC, serverAddr).Dial()
	a.NoError(err, "stats: %+v", l.(*pathListener).srv.Stats())
	t.Cleanup(func() { _ = real.CloseAbort() })
	srv := recv(t, sessions)
	t.Cleanup(func() { _ = srv.CloseAbort() })
	sendRecv(t, real, srv, []byte("ninth network"))
	sendRecv(t, srv, real, []byte("ninth network, reply"))

	// One INIT from the new network evicts one accepted path. A retransmit
	// of that same INIT does not insert another path, so Evicted grows by 1.
	after := l.(*pathListener).srv.Stats()
	a.Equal(before.Evicted+1, after.Evicted)

	failWait := time.NewTimer(udpTimeout)
	defer failWait.Stop()
	var failed error
	select {
	case failed = <-errc:
	case <-failWait.C:
		a.FailNow("no attacker handshake failed")
	}
	a.Error(failed)
	a.ErrorIs(failed, ErrConnClosed)

	// The other 255 dials are still blocked in the handshake.
	quiet := time.NewTimer(300 * time.Millisecond)
	defer quiet.Stop()
	select {
	case err := <-errc:
		t.Fatalf("another attacker dial returned: %v", err)
	case <-quiet.C:
	}
}
