package udppath

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/internal/udppath/udptest"
)

// pathPair is an established client path and the responder's server path.
type pathPair struct {
	n      *udptest.Net
	r      *responder
	client *Path
	server *Path
}

// establish dials the test responder and returns both ends, not started.
func establish(t *testing.T) pathPair {
	t.Helper()
	a := require.New(t)
	n := udptest.New()
	r := startResponder(t, n, nil)
	pc := dialPC(t, n)
	p, err := Dial(testCtx(t, 5*time.Second), pc, r.addr(), Config{})
	a.NoError(err)
	t.Cleanup(func() { _ = p.Close() })
	return pathPair{n: n, r: r, client: p, server: r.pathFor(t, p.sid)}
}

// started establishes and starts both ends.
func started(t *testing.T) pathPair {
	t.Helper()
	pp := establish(t)
	pp.client.Start()
	pp.server.Start()
	return pp
}

type readResult struct {
	err  error
	addr net.Addr
	data []byte
}

// readAsync runs one ReadFrom on p in the background.
func readAsync(p *Path) <-chan readResult {
	ch := make(chan readResult, 1)
	go func() {
		buf := make([]byte, readBufSize)
		n, addr, err := p.ReadFrom(buf)
		ch <- readResult{data: buf[:n], addr: addr, err: err}
	}()
	return ch
}

// readWithin runs one ReadFrom on p and fails the test if it takes over a
// second.
func readWithin(t *testing.T, p *Path) readResult {
	t.Helper()
	select {
	case res := <-readAsync(p):
		return res
	case <-time.After(time.Second):
		require.New(t).FailNow("ReadFrom did not return")
		return readResult{}
	}
}

func write(t *testing.T, p *Path, data []byte) {
	t.Helper()
	n, err := p.WriteTo(data, nil)
	a := require.New(t)
	a.NoError(err)
	a.Equal(len(data), n)
}

func TestPathData(t *testing.T) {
	a := require.New(t)
	pp := started(t)

	write(t, pp.client, []byte("hello"))
	res := readWithin(t, pp.server)
	a.NoError(res.err)
	a.Equal([]byte("hello"), res.data)
	a.Same(pp.server.RemoteUDPAddr(), res.addr)
	a.Equal(pp.client.LocalAddr().String(), res.addr.String())

	full := bytes.Repeat([]byte{0xAB}, KCPMTU)
	write(t, pp.server, full)
	res = readWithin(t, pp.client)
	a.NoError(res.err)
	a.Equal(full, res.data)
	a.Same(pp.client.RemoteUDPAddr(), res.addr)

	for _, size := range []int{0, KCPMTU + 1} {
		_, err := pp.client.WriteTo(make([]byte, size), nil)
		a.ErrorIs(err, errPacketSize, "size %d", size)
	}
	a.NoError(pp.client.SetDeadline(time.Now()))
	a.NoError(pp.client.SetReadDeadline(time.Now()))
	a.NoError(pp.client.SetWriteDeadline(time.Now()))
}

func TestPathWaitsForStart(t *testing.T) {
	a := require.New(t)
	pp := establish(t)
	pp.server.Start()
	write(t, pp.server, []byte("early"))

	ch := readAsync(pp.client)
	select {
	case res := <-ch:
		a.FailNow("ReadFrom returned before Start", "%v", res)
	case <-time.After(50 * time.Millisecond):
	}
	pp.client.Start()
	select {
	case res := <-ch:
		a.NoError(res.err)
		a.Equal([]byte("early"), res.data)
	case <-time.After(time.Second):
		a.FailNow("ReadFrom did not return after Start")
	}
}

// TestPathInputChecks injects DATA at the client socket and checks which of
// it reaches ReadFrom.
func TestPathInputChecks(t *testing.T) {
	a := require.New(t)
	pp := started(t)
	from := pp.r.addr()
	to := pp.client.pc.LocalAddr().(*net.UDPAddr).AddrPort()
	seal := func(rid uint32, ctr uint64) []byte {
		return sealPacket(
			nil, pp.server.send, typeData, rid, ctr,
			fmt.Appendf(nil, "%d", ctr),
		)
	}
	cid := pp.client.cid
	stranger := netip.MustParseAddrPort("192.0.2.99:1")
	badTag := seal(cid, 11)
	badTag[len(badTag)-1] ^= 1
	sends := []struct {
		pkt  []byte
		from netip.AddrPort
	}{
		{seal(cid, 10), from},                // delivered
		{seal(cid, 10), from},                // replay
		{seal(cid+1, 12), from},              // unknown rid
		{seal(cid, 13), stranger},            // right rid, other address
		{badTag, from},                       // bad tag
		{seal(cid, 5), from},                 // out of order, delivered
		{seal(cid, 5), from},                 // replay
		{seal(cid, 5000), from},              // far jump, delivered
		{seal(cid, 5000-ReplayWindow), from}, // older than the window
		{seal(cid, 11), from},                // older than the window
		{seal(cid, 6000), from},              // delivered, last
	}
	before := pp.client.Stats()
	for _, s := range sends {
		pp.n.Inject(s.from, to, s.pkt)
	}
	var got []string
	for len(got) < 4 {
		res := readWithin(t, pp.client)
		a.NoError(res.err)
		got = append(got, string(res.data))
	}
	a.Equal([]string{"10", "5", "5000", "6000"}, got)
	after := pp.client.Stats()
	a.Equal(uint64(4), after.Replay-before.Replay)
	a.Equal(uint64(2), after.NoPath-before.NoPath)
	a.Equal(uint64(1), after.BadTag-before.BadTag)
}

func TestPathUnexpectedAfterEstablished(t *testing.T) {
	a := require.New(t)
	pp := started(t)
	to := pp.client.pc.LocalAddr().(*net.UDPAddr).AddrPort()
	var cookie [cookieLen]byte
	pp.n.Inject(pp.r.addr(), to, encodeCookie(pp.client.cid, cookie))
	write(t, pp.server, []byte("after"))
	res := readWithin(t, pp.client)
	a.NoError(res.err)
	a.Equal(uint64(1), pp.client.Stats().Unexpected)
}

func TestPathPeerClose(t *testing.T) {
	a := require.New(t)
	pp := started(t)
	write(t, pp.server, []byte("last"))
	a.NoError(pp.server.Close())

	res := readWithin(t, pp.client)
	a.NoError(res.err)
	a.Equal([]byte("last"), res.data)
	res = readWithin(t, pp.client)
	a.ErrorIs(res.err, ErrPathClosed)
	a.ErrorIs(res.err, net.ErrClosed)
	_, err := pp.client.WriteTo([]byte("x"), nil)
	a.ErrorIs(err, ErrPathClosed)

	st := pp.client.Stats()
	a.Zero(st.CloseSent, "a peer's CLOSE gets no CLOSE back")
	a.GreaterOrEqual(st.CloseReceived, uint64(1))
	a.Equal(uint64(2), pp.r.stats.CloseSent.Load())

	res = readWithin(t, pp.server)
	a.ErrorIs(res.err, ErrPathClosed)
}

func TestPathBadTagClose(t *testing.T) {
	a := require.New(t)
	pp := started(t)
	to := pp.client.pc.LocalAddr().(*net.UDPAddr).AddrPort()
	bad := sealPacket(nil, pp.server.send, typeClose, pp.client.cid, 50, nil)
	bad[CloseSize-1] ^= 1
	pp.n.Inject(pp.r.addr(), to, bad)
	write(t, pp.server, []byte("still open"))
	res := readWithin(t, pp.client)
	a.NoError(res.err)
	a.Equal([]byte("still open"), res.data)
	a.Equal(uint64(1), pp.client.Stats().BadTag)
	a.Zero(pp.client.Stats().CloseReceived)
}

func TestPathClientClose(t *testing.T) {
	a := require.New(t)
	pp := started(t)
	a.NoError(pp.client.Close())
	a.NoError(pp.client.Close())

	res := readWithin(t, pp.server)
	a.ErrorIs(res.err, ErrPathClosed)
	a.Equal(uint64(2), pp.client.Stats().CloseSent)

	select {
	case <-pp.client.rd.done:
	case <-time.After(time.Second):
		a.FailNow("the client reader did not end")
	}
	_, err := pp.client.pc.WriteTo([]byte{0}, pp.client.RemoteUDPAddr())
	a.ErrorIs(err, net.ErrClosed, "Close closes the client socket")
	_, err = pp.client.WriteTo([]byte("x"), nil)
	a.ErrorIs(err, ErrPathClosed)
	res = readWithin(t, pp.client)
	a.ErrorIs(res.err, ErrPathClosed)
}

func TestPathSocketClosed(t *testing.T) {
	a := require.New(t)
	pp := started(t)
	a.NoError(pp.client.pc.Close())
	res := readWithin(t, pp.client)
	a.ErrorIs(res.err, ErrPathClosed)
	<-pp.client.rd.done
	a.Zero(pp.client.Stats().CloseSent)
}

func TestPathCounterExhausted(t *testing.T) {
	a := require.New(t)
	pp := started(t)
	pp.client.sendCtr.Store(maxCounter - 1)
	_, err := pp.client.WriteTo([]byte("x"), nil)
	a.ErrorIs(err, ErrPathClosed)
	res := readWithin(t, pp.client)
	a.ErrorIs(res.err, ErrPathClosed)
	a.Zero(pp.client.Stats().CloseSent, "no counter is left for CLOSE")
}

func TestPathInboundFull(t *testing.T) {
	a := require.New(t)
	pp := establish(t)
	pp.server.Start()
	for i := range PathInbound + 2 {
		write(t, pp.server, []byte{byte(i)})
	}
	deadline := time.Now().Add(2 * time.Second)
	for pp.client.Stats().InboundDropped < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	a.Equal(uint64(2), pp.client.Stats().InboundDropped)
	pp.client.Start()
	for i := range PathInbound {
		res := readWithin(t, pp.client)
		a.NoError(res.err)
		a.Equal([]byte{byte(i)}, res.data)
	}
}

func TestPathConcurrent(t *testing.T) {
	a := require.New(t)
	pp := started(t)
	const writers, perWriter = 4, 25
	const total = writers * perWriter

	readAll := func(p *Path, got *atomic.Int64) <-chan struct{} {
		done := make(chan struct{})
		go func() {
			defer close(done)
			buf := make([]byte, KCPMTU)
			for {
				if _, _, err := p.ReadFrom(buf); err != nil {
					return
				}
				got.Add(1)
			}
		}()
		return done
	}
	var clientGot, serverGot atomic.Int64
	clientDone := readAll(pp.client, &clientGot)
	serverDone := readAll(pp.server, &serverGot)

	var wg sync.WaitGroup
	for range writers {
		wg.Go(func() {
			for range perWriter {
				_, err := pp.client.WriteTo([]byte("c"), nil)
				a.NoError(err)
			}
		})
		wg.Go(func() {
			for range perWriter {
				_, err := pp.server.WriteTo([]byte("s"), nil)
				a.NoError(err)
			}
		})
	}
	wg.Wait()

	// A packet the path queue had no room for is counted as dropped, so
	// every packet is either read or counted.
	settled := func() bool {
		c := clientGot.Load() + int64(pp.client.Stats().InboundDropped)
		s := serverGot.Load() + int64(pp.r.stats.InboundDropped.Load())
		return c == total && s == total
	}
	deadline := time.Now().Add(2 * time.Second)
	for !settled() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	a.True(settled())
	a.NoError(pp.server.Close())
	a.NoError(pp.client.Close())
	<-clientDone
	<-serverDone
}
