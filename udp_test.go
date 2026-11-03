package kamune

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/internal/clock"
	"github.com/kamune-org/kamune/internal/udppath"
	"github.com/kamune-org/kamune/internal/udppath/udptest"
	"github.com/kamune-org/kamune/pkg/storage"
)

// Packet types of the path layer, as internal/udppath/wire.go defines them.
const (
	udpTypeHello  = 0x01
	udpTypeInit   = 0x03
	udpTypeAccept = 0x04
	udpTypeData   = 0x05
	udpTypeClose  = 0x06
)

// kcpPushCmd is the command of a KCP segment that pushes data.
const kcpPushCmd = 81

// foreignConv is a KCP conversation that no path uses. Its first byte is
// above the range of the path layer, so a datagram of it is foreign.
const foreignConv = 0xfeedface

// udpTimeout bounds each wait of these tests. A wait that runs this long has
// failed.
const udpTimeout = 10 * time.Second

// allowAll is a RemoteVerifier that accepts every peer.
func allowAll(context.Context, *storage.Storage, VerifyRequest) error {
	return nil
}

// udpPair returns a udptest network with a socket for a server and one for a
// dialer.
func udpPair(t *testing.T) (*udptest.Net, net.PacketConn, net.PacketConn) {
	t.Helper()
	a := require.New(t)
	n := udptest.New()
	serverPC, err := n.Listen("127.0.0.1:0")
	a.NoError(err)
	clientPC, err := n.Listen("127.0.0.1:0")
	a.NoError(err)
	return n, serverPC, clientPC
}

// udpAddrPort returns the address of a socket of a udptest network.
func udpAddrPort(pc net.PacketConn) netip.AddrPort {
	return pc.LocalAddr().(*net.UDPAddr).AddrPort()
}

// udpServe runs a kamune server on addr with the options opt. Each session it
// accepts goes to the returned channel. Its handler keeps the session until the
// returned release func is called, because a handler that returns closes an
// unreleased transport. Release runs before the server's storage closes.
func udpServe(
	t *testing.T, addr string, opt ServerOptions,
) (*Server, <-chan *Transport, func()) {
	t.Helper()
	a := require.New(t)
	store, cleanup := newTestStore(t)
	t.Cleanup(cleanup)
	hold, release := newGate(t)
	sessions := make(chan *Transport, 8)
	server, err := NewServer(
		addr,
		func(tr *Transport) error {
			sessions <- tr
			<-hold
			return nil
		},
		store,
		allowAll,
		opt,
	)
	a.NoError(err)
	go func() { _ = server.ListenAndServe() }()
	t.Cleanup(func() {
		// Shutdown waits for the handler, so the store closes after it.
		release()
		ctx, cancel := context.WithTimeout(context.Background(), udpTimeout)
		defer cancel()
		_ = server.Shutdown(ctx)
	})
	return server, sessions, release
}

// udpWithClock is a UDPOption that sets the clock of the path layer of a
// server.
func udpWithClock(c clock.Clock) UDPOption {
	return func(cfg *udpConfig) error {
		cfg.clock = c
		return nil
	}
}

// pathDial is a DialOption that dials over the path layer from pc.
func pathDial(pc net.PacketConn) DialOption {
	return DialWithFunc(func(addr string) (Conn, error) {
		ap, err := netip.ParseAddrPort(addr)
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), udpTimeout)
		defer cancel()
		return DialUDP(ctx, pc, ap)
	})
}

// udpDialer returns a dialer of the server at addr, which dials from pc over
// the path layer.
func udpDialer(
	t *testing.T, store *storage.Storage, pc net.PacketConn, addr string,
) *Dialer {
	t.Helper()
	dialer, err := NewDialer(addr, store, allowAll, pathDial(pc))
	require.NoError(t, err)
	return dialer
}

// udpDial dials the server at addr from pc over the path layer, with a store
// of its own, and returns the session.
func udpDial(t *testing.T, pc net.PacketConn, addr string) (*Transport, error) {
	t.Helper()
	store, cleanup := newTestStore(t)
	t.Cleanup(cleanup)
	return udpDialer(t, store, pc, addr).Dial()
}

// sendRecv sends msg from one end of a session to the other, and checks that
// it arrives intact.
func sendRecv(t *testing.T, from, to *Transport, msg []byte) {
	t.Helper()
	a := require.New(t)
	_, err := from.Send(Bytes(msg), RouteExchangeMessages)
	a.NoError(err)
	a.NoError(to.SetDeadline(time.Now().Add(udpTimeout)))
	got := Bytes(nil)
	_, err = to.Receive(got)
	a.NoError(err)
	a.Equal(msg, got.Value)
}

// recv returns the next value of ch, and fails the test when none comes in
// time.
func recv[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(udpTimeout):
		t.Fatal("timed out waiting for a value")
		var zero T
		return zero
	}
}

// pathOf returns the path under a session that runs over the path layer.
func pathOf(tr *Transport) *udppath.Path {
	return tr.conn.(*conn).conn.(*kcpPath).path
}

// remoteOf returns the address of the peer of a session that runs over the
// path layer.
func remoteOf(tr *Transport) netip.AddrPort {
	return tr.conn.(*conn).RemoteAddr().(*net.UDPAddr).AddrPort()
}

// acceptSpy is a udptest filter that reports the ids of the first ACCEPT that
// the server sends.
type acceptSpy struct {
	server netip.AddrPort
	ids    chan [2]uint32
	once   sync.Once
}

func newAcceptSpy(server netip.AddrPort) *acceptSpy {
	return &acceptSpy{server: server, ids: make(chan [2]uint32, 1)}
}

// observe is a udptest filter. It delivers every datagram once.
func (s *acceptSpy) observe(from, _ netip.AddrPort, pkt []byte) int {
	if from == s.server && len(pkt) == udppath.AcceptSize &&
		pkt[0] == udpTypeAccept {
		s.once.Do(func() {
			// An ACCEPT holds the client id at 4 and the server id at 8.
			s.ids <- [2]uint32{
				binary.BigEndian.Uint32(pkt[4:]),
				binary.BigEndian.Uint32(pkt[8:]),
			}
		})
	}
	return 1
}

// kcpSegment returns a KCP segment of conversation conv, with command cmd, no
// sequence number and the payload.
func kcpSegment(conv uint32, cmd byte, payload []byte) []byte {
	b := make([]byte, 24+len(payload))
	binary.LittleEndian.PutUint32(b[0:], conv)
	b[4] = cmd
	binary.LittleEndian.PutUint16(b[6:], 128)
	binary.LittleEndian.PutUint32(b[20:], uint32(len(payload)))
	copy(b[24:], payload)
	return b
}

// pathPacket returns a DATA or CLOSE of the path layer, of size bytes, for the
// id rid and the counter ctr. Its tag is garbage.
func pathPacket(typ byte, rid uint32, ctr uint64, size int) []byte {
	b := make([]byte, size)
	b[0], b[1] = typ, udppath.Version
	binary.BigEndian.PutUint32(b[4:], rid)
	binary.BigEndian.PutUint64(b[8:], ctr)
	for i := 16; i < size; i++ {
		b[i] = 0xa5
	}
	return b
}

// TestUDPForeignAndForgedPacketsLeaveSession is the regression test of KAM-11.
// A raw KCP header, a KCP segment of a foreign conversation, a forged CLOSE and
// a DATA for no path, sent from the dialer's address or from the server's, are
// counted and dropped, and the session still works afterwards.
func TestUDPForeignAndForgedPacketsLeaveSession(t *testing.T) {
	a := require.New(t)
	n, serverPC, clientPC := udpPair(t)
	serverAddr, clientAddr := udpAddrPort(serverPC), udpAddrPort(clientPC)
	spy := newAcceptSpy(serverAddr)
	n.SetFilter(spy.observe)

	l, err := ListenUDP(serverPC)
	a.NoError(err)
	_, sessions, _ := udpServe(t, "", ServeWithListener(l))
	cli, err := udpDial(t, clientPC, serverAddr.String())
	a.NoError(err)
	t.Cleanup(func() { _ = cli.Close() })
	srv := recv(t, sessions)
	ids := recv(t, spy.ids)
	cid, sid := ids[0], ids[1]
	unknown := uint32(0x0bad1d0a)
	for unknown == cid || unknown == sid {
		unknown++
	}

	pl := l.(*pathListener)
	before := pl.srv.Stats()
	n.Inject(clientAddr, serverAddr, kcpSegment(1, 0, nil))
	n.Inject(clientAddr, serverAddr,
		kcpSegment(foreignConv, kcpPushCmd, []byte{0}))
	n.Inject(clientAddr, serverAddr,
		pathPacket(udpTypeClose, sid, 1<<40, udppath.CloseSize))
	n.Inject(clientAddr, serverAddr,
		pathPacket(udpTypeData, unknown, 1, udppath.DataOverhead+1))
	a.Eventually(func() bool {
		s := pl.srv.Stats()
		return s.Malformed > before.Malformed &&
			s.Foreign > before.Foreign &&
			s.NoPath > before.NoPath &&
			s.BadTag > before.BadTag
	}, udpTimeout, 5*time.Millisecond)
	sendRecv(t, cli, srv, []byte("dialer, after the server's counters"))
	sendRecv(t, srv, cli, []byte("server, after the server's counters"))

	// The same packets from the server's address to the dialer.
	cliBefore := pathOf(cli).Stats()
	n.Inject(serverAddr, clientAddr, kcpSegment(1, 0, nil))
	n.Inject(serverAddr, clientAddr,
		kcpSegment(foreignConv, kcpPushCmd, []byte{0}))
	n.Inject(serverAddr, clientAddr,
		pathPacket(udpTypeClose, cid, 1<<40, udppath.CloseSize))
	n.Inject(serverAddr, clientAddr,
		pathPacket(udpTypeData, unknown, 1, udppath.DataOverhead+1))
	a.Eventually(func() bool {
		s := pathOf(cli).Stats()
		return s.Malformed > cliBefore.Malformed &&
			s.Foreign > cliBefore.Foreign &&
			s.NoPath > cliBefore.NoPath &&
			s.BadTag > cliBefore.BadTag
	}, udpTimeout, 5*time.Millisecond)
	sendRecv(t, cli, srv, []byte("dialer, after the dialer's counters"))
	sendRecv(t, srv, cli, []byte("server, after the dialer's counters"))
}

// TestDialUDPUnreachableServerTimesOut checks that a dial to a socket that
// never answers fails with ErrUDPHandshakeTimeout within the dial timeout.
func TestDialUDPUnreachableServerTimesOut(t *testing.T) {
	a := require.New(t)
	silent, err := net.ListenUDP(
		"udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
	)
	a.NoError(err)
	t.Cleanup(func() { _ = silent.Close() })
	store, cleanup := newTestStore(t)
	t.Cleanup(cleanup)
	dialer, err := NewDialer(
		silent.LocalAddr().String(), store, allowAll,
		DialWithUDP(), DialWithDialTimeout(500*time.Millisecond),
	)
	a.NoError(err)

	start := time.Now()
	_, err = dialer.Dial()
	a.ErrorIs(err, ErrUDPHandshakeTimeout)
	a.Less(time.Since(start), time.Second)
}

// TestUDPServerExpiresHalfOpenPath drops every DATA of the dialer, so that the
// server's path never opens. Once the fake clock passes the HALF_OPEN timeout,
// the server expires the path and sends CLOSE, and the dial fails with
// ErrConnClosed well before the handshake timeout.
func TestUDPServerExpiresHalfOpenPath(t *testing.T) {
	a := require.New(t)
	n, serverPC, clientPC := udpPair(t)
	serverAddr, clientAddr := udpAddrPort(serverPC), udpAddrPort(clientPC)
	spy := newAcceptSpy(serverAddr)
	n.SetFilter(func(from, to netip.AddrPort, pkt []byte) int {
		spy.observe(from, to, pkt)
		if from == clientAddr && len(pkt) > 0 && pkt[0] == udpTypeData {
			return 0
		}
		return 1
	})
	fake := clock.NewFake(time.Now())
	l, err := ListenUDP(serverPC, udpWithClock(fake))
	a.NoError(err)
	udpServe(t, "", ServeWithListener(l))

	store, cleanup := newTestStore(t)
	t.Cleanup(cleanup)
	dialer := udpDialer(t, store, clientPC, serverAddr.String())
	start := time.Now()
	dialed := make(chan error, 1)
	go func() {
		_, err := dialer.Dial()
		dialed <- err
	}()
	// The path opens when the server sends its ACCEPT. The clock moves on
	// from there, so the path is still HALF_OPEN when it expires.
	recv(t, spy.ids)
	fake.Advance(udppath.HalfOpenTimeout + time.Second)
	a.ErrorIs(recv(t, dialed), ErrConnClosed)
	a.Less(time.Since(start), defaultHandshakeTimeout)
}

// TestUDPLargeFrameRoundTrip sends the largest frame that kamune hands to a
// Conn in both directions. The frame is maxFrameSize (65,471) bytes, and it
// seals a user message of maxTransportSize-64 bytes, as
// TestTransport_LargestFrameFitsRelayWrapping checks.
func TestUDPLargeFrameRoundTrip(t *testing.T) {
	a := require.New(t)
	_, serverPC, clientPC := udpPair(t)
	l, err := ListenUDP(serverPC)
	a.NoError(err)
	_, sessions, _ := udpServe(t, "", ServeWithListener(l))
	cli, err := udpDial(t, clientPC, udpAddrPort(serverPC).String())
	a.NoError(err)
	t.Cleanup(func() { _ = cli.Close() })
	srv := recv(t, sessions)

	payload := make([]byte, maxTransportSize-64)
	_, err = rand.Read(payload)
	a.NoError(err)
	sendRecv(t, cli, srv, payload)
	sendRecv(t, srv, cli, payload)
}

// TestUDPServerCloseKeepsSession closes the server while a session is open.
// The session keeps working, and Shutdown waits for its handler, as it does
// for TCP.
func TestUDPServerCloseKeepsSession(t *testing.T) {
	a := require.New(t)
	_, serverPC, clientPC := udpPair(t)
	l, err := ListenUDP(serverPC)
	a.NoError(err)
	server, sessions, release := udpServe(t, "", ServeWithListener(l))
	cli, err := udpDial(t, clientPC, udpAddrPort(serverPC).String())
	a.NoError(err)
	srv := recv(t, sessions)

	a.NoError(server.Close())
	sendRecv(t, cli, srv, []byte("sent after the server closed"))
	sendRecv(t, srv, cli, []byte("answer after the server closed"))

	shut := make(chan error, 1)
	go func() { shut <- server.Shutdown(context.Background()) }()
	select {
	case err := <-shut:
		t.Fatalf("Shutdown returned while the session was open: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	a.NoError(cli.Close())
	a.NoError(srv.Close())
	release()
	a.NoError(recv(t, shut))
}

// TestUDPRedialFromSameSource ends a session, binds the dialer's address
// again, and dials from it. The new dial completes a kamune handshake over a
// new path.
func TestUDPRedialFromSameSource(t *testing.T) {
	a := require.New(t)
	n, serverPC, clientPC := udpPair(t)
	serverAddr := udpAddrPort(serverPC).String()
	clientAddr := udpAddrPort(clientPC)
	l, err := ListenUDP(serverPC)
	a.NoError(err)
	_, sessions, _ := udpServe(t, "", ServeWithListener(l))
	store, cleanup := newTestStore(t)
	t.Cleanup(cleanup)

	cli, err := udpDialer(t, store, clientPC, serverAddr).Dial()
	a.NoError(err)
	srv := recv(t, sessions)
	sendRecv(t, cli, srv, []byte("first session"))
	sendRecv(t, srv, cli, []byte("first session, answer"))
	// Closing the session closes the dialer's socket, so its address is free.
	a.NoError(cli.Close())

	again, err := n.Listen(clientAddr.String())
	a.NoError(err)
	cli2, err := udpDialer(t, store, again, serverAddr).Dial()
	a.NoError(err)
	t.Cleanup(func() { _ = cli2.Close() })
	srv2 := recv(t, sessions)
	sendRecv(t, cli2, srv2, []byte("second session"))
	sendRecv(t, srv2, cli2, []byte("second session, answer"))
	a.Equal(clientAddr, remoteOf(srv2))
	a.NotEqual(pathOf(cli).Conv(), pathOf(cli2).Conv())
}

// TestUDPPathCountsAgainstPerSourceCapAtAccept checks that a path counts
// against ServeWithMaxPendingPerSource when the server accepts it, as a TCP
// connection does, and not only once its dialer has authenticated. The server
// allows one connection per source. Two dialers share an IP address, and each
// path is taken from Accept and passed to admit directly, so the check is
// deterministic: admit takes the first path and refuses the second before any
// kamune handshake message is read.
func TestUDPPathCountsAgainstPerSourceCapAtAccept(t *testing.T) {
	a := require.New(t)
	n, serverPC, firstPC := udpPair(t)
	secondPC, err := n.Listen("127.0.0.1:0")
	a.NoError(err)
	serverAddr := udpAddrPort(serverPC)
	l, err := ListenUDP(serverPC)
	a.NoError(err)
	t.Cleanup(func() { _ = l.Close() })

	store, cleanup := newTestStore(t)
	t.Cleanup(cleanup)
	server, err := NewServer(
		"",
		func(*Transport) error { return nil },
		store,
		allowAll,
		ServeWithListener(l),
		ServeWithMaxPendingPerSource(1),
	)
	a.NoError(err)

	// dialPath runs the path handshake from pc and sends one datagram, which
	// makes the path ready for Accept.
	dialPath := func(pc net.PacketConn) {
		ctx, cancel := context.WithTimeout(context.Background(), udpTimeout)
		defer cancel()
		cn, err := DialUDP(ctx, pc, serverAddr)
		a.NoError(err)
		t.Cleanup(func() { _ = cn.Close() })
		a.NoError(cn.WriteBytes([]byte("hello")))
	}
	// accept returns the next path of l, once its dialer has sent data.
	type accepted struct {
		cn  Conn
		err error
	}
	accept := func() Conn {
		got := make(chan accepted, 1)
		go func() {
			cn, err := l.Accept()
			got <- accepted{cn: cn, err: err}
		}()
		r := recv(t, got)
		a.NoError(r.err)
		t.Cleanup(func() { _ = r.cn.Close() })
		return r.cn
	}

	dialPath(firstPC)
	first := accept()
	_, _, ok := server.admit(first)
	a.True(ok, "the first connection of a source was refused")

	dialPath(secondPC)
	second := accept()
	_, _, ok = server.admit(second)
	a.False(ok, "a second connection from the same source was admitted")
}

// TestUDPDualStack serves ServeWithUDP on a dual-stack socket and dials it
// once over IPv4 and once over IPv6, on real sockets. Both dials complete a
// handshake, and the server keys the IPv4 session by its unmapped address.
func TestUDPDualStack(t *testing.T) {
	probe, err := net.ListenUDP(
		"udp6", &net.UDPAddr{IP: net.IPv6loopback},
	)
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	_ = probe.Close()

	a := require.New(t)
	store, cleanup := newTestStore(t)
	t.Cleanup(cleanup)
	server, sessions, _ := udpServe(t, "[::]:0", ServeWithUDP())
	pl := server.listener.(*pathListener)
	port := pl.srv.Addr().(*net.UDPAddr).Port

	d4, err := NewDialer(
		fmt.Sprintf("127.0.0.1:%d", port), store, allowAll, DialWithUDP(),
	)
	a.NoError(err)
	d6, err := NewDialer(
		fmt.Sprintf("[::1]:%d", port), store, allowAll, DialWithUDP(),
	)
	a.NoError(err)
	c4, err := d4.Dial()
	a.NoError(err, "server stats: %+v", pl.srv.Stats())
	t.Cleanup(func() { _ = c4.Close() })
	c6, err := d6.Dial()
	a.NoError(err, "server stats: %+v", pl.srv.Stats())
	t.Cleanup(func() { _ = c6.Close() })

	// The server's sessions are told apart by the dialer's port.
	byPort := make(map[int]*Transport)
	for range 2 {
		srv := recv(t, sessions)
		byPort[int(remoteOf(srv).Port())] = srv
	}
	port4 := c4.conn.(*conn).LocalAddr().(*net.UDPAddr).Port
	port6 := c6.conn.(*conn).LocalAddr().(*net.UDPAddr).Port
	a.Equal(netip.MustParseAddr("127.0.0.1"), remoteOf(byPort[port4]).Addr())
	a.Equal(netip.MustParseAddr("::1"), remoteOf(byPort[port6]).Addr())
	sendRecv(t, c4, byPort[port4], []byte("over IPv4"))
	sendRecv(t, byPort[port4], c4, []byte("answer over IPv4"))
	sendRecv(t, c6, byPort[port6], []byte("over IPv6"))
	sendRecv(t, byPort[port6], c6, []byte("answer over IPv6"))
}

// TestUDPCloseLinger ends a session from the dialer's side. When the close
// frame reaches the server, the server's Receive reports the graceful close.
// When the frame is lost, the server learns of the close from CLOSE, and its
// Receive reports the dropped connection.
func TestUDPCloseLinger(t *testing.T) {
	cases := []struct {
		name string
		// dropData drops the dialer's DATA from the moment it closes.
		dropData bool
		want     error
	}{
		{name: "frame delivered", want: ErrPeerDisconnected},
		{name: "frame lost", dropData: true, want: ErrConnClosed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			n, serverPC, clientPC := udpPair(t)
			serverAddr := udpAddrPort(serverPC)
			clientAddr := udpAddrPort(clientPC)
			var drop atomic.Bool
			n.SetFilter(func(from, _ netip.AddrPort, pkt []byte) int {
				if drop.Load() && from == clientAddr && len(pkt) > 0 &&
					pkt[0] == udpTypeData {
					return 0
				}
				return 1
			})
			l, err := ListenUDP(serverPC)
			a.NoError(err)
			_, sessions, _ := udpServe(t, "", ServeWithListener(l))
			cli, err := udpDial(t, clientPC, serverAddr.String())
			a.NoError(err)
			srv := recv(t, sessions)
			sendRecv(t, cli, srv, []byte("hello"))

			drop.Store(tc.dropData)
			a.NoError(cli.Close())
			a.NoError(srv.SetDeadline(time.Now().Add(udpTimeout)))
			_, err = srv.Receive(Bytes(nil))
			a.ErrorIs(err, tc.want)
		})
	}
}

// TestKcpPathCheckSkipsTimeouts checks which read or write errors count as a
// failure of a session. A timeout does not: the session goes on after it, so
// its close still lingers. A closed path is a failure, and it surfaces as
// ErrConnClosed.
func TestKcpPathCheckSkipsTimeouts(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		failed     bool
		connClosed bool
	}{
		{name: "deadline", err: os.ErrDeadlineExceeded},
		{
			name: "closed path", err: net.ErrClosed,
			failed: true, connClosed: true,
		},
		{name: "other", err: errors.New("broken"), failed: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			var c kcpPath
			got := c.check(tc.err)
			a.Equal(tc.failed, c.failed.Load())
			a.ErrorIs(got, tc.err)
			a.Equal(tc.connClosed, errors.Is(got, ErrConnClosed))
		})
	}
}
