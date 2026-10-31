package udptest

import (
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDeliver(t *testing.T) {
	a := require.New(t)
	n := New()
	src := listen(t, n)
	dst := listen(t, n)

	a.Equal("udp", src.LocalAddr().Network())
	a.NotEqual(src.LocalAddr().String(), dst.LocalAddr().String())
	srcUDP := src.LocalAddr().(*net.UDPAddr)
	a.Equal("127.0.0.1", srcUDP.IP.String())
	a.NotZero(srcUDP.Port)

	payload := []byte("hello")
	sent := append([]byte(nil), payload...)
	nw, err := src.WriteTo(sent, dst.LocalAddr())
	a.NoError(err)
	a.Equal(len(payload), nw)
	sent[0] = 'X'

	got, addr := readFrom(t, dst)
	a.Equal(payload, got)
	a.Equal(src.LocalAddr().String(), addr.String())
}

func TestInjectFromNowhere(t *testing.T) {
	a := require.New(t)
	n := New()
	dst := listen(t, n)
	to := dst.LocalAddr().(*net.UDPAddr).AddrPort()
	from := netip.MustParseAddrPort("192.0.2.8:4000")

	payload := []byte("ext")
	sent := append([]byte(nil), payload...)
	n.Inject(from, to, sent)
	sent[0] = 'Z'

	got, addr := readFrom(t, dst)
	a.Equal(payload, got)
	a.Equal(from, addr.(*net.UDPAddr).AddrPort())
}

func TestFilterDrop(t *testing.T) {
	a := require.New(t)
	n := New()
	src := listen(t, n)
	dst := listen(t, n)
	n.SetFilter(func(from, to netip.AddrPort, pkt []byte) int {
		a.Equal(src.LocalAddr().(*net.UDPAddr).AddrPort(), from)
		a.Equal(dst.LocalAddr().(*net.UDPAddr).AddrPort(), to)
		a.Equal([]byte("nope"), pkt)
		return 0
	})

	nw, err := src.WriteTo([]byte("nope"), dst.LocalAddr())
	a.NoError(err)
	a.Equal(4, nw)

	a.NoError(dst.SetReadDeadline(time.Now().Add(40 * time.Millisecond)))
	_, _, err = dst.ReadFrom(make([]byte, 8))
	a.ErrorIs(err, os.ErrDeadlineExceeded)
}

func TestFilterDuplicate(t *testing.T) {
	a := require.New(t)
	n := New()
	src := listen(t, n)
	dst := listen(t, n)
	calls := 0
	n.SetFilter(func(from, to netip.AddrPort, pkt []byte) int {
		calls++
		a.Equal(src.LocalAddr().(*net.UDPAddr).AddrPort(), from)
		a.Equal(dst.LocalAddr().(*net.UDPAddr).AddrPort(), to)
		a.Equal([]byte("dup"), pkt)
		return 2
	})

	_, err := src.WriteTo([]byte("dup"), dst.LocalAddr())
	a.NoError(err)
	a.Equal(1, calls)

	first, addr1 := readFrom(t, dst)
	second, addr2 := readFrom(t, dst)
	a.Equal([]byte("dup"), first)
	a.Equal([]byte("dup"), second)
	a.Equal(src.LocalAddr().String(), addr1.String())
	a.Equal(src.LocalAddr().String(), addr2.String())

	a.NoError(dst.SetReadDeadline(time.Now().Add(40 * time.Millisecond)))
	_, _, err = dst.ReadFrom(make([]byte, 8))
	a.ErrorIs(err, os.ErrDeadlineExceeded)
}

func TestReadDeadline(t *testing.T) {
	a := require.New(t)
	n := New()
	c := listen(t, n)

	a.NoError(c.SetReadDeadline(time.Now().Add(40 * time.Millisecond)))
	_, _, err := c.ReadFrom(make([]byte, 8))
	a.ErrorIs(err, os.ErrDeadlineExceeded)

	a.NoError(c.SetReadDeadline(time.Now().Add(-time.Millisecond)))
	_, _, err = c.ReadFrom(make([]byte, 8))
	a.ErrorIs(err, os.ErrDeadlineExceeded)

	errc := make(chan error, 1)
	a.NoError(c.SetReadDeadline(time.Time{}))
	go func() {
		_, _, rerr := c.ReadFrom(make([]byte, 8))
		errc <- rerr
	}()
	select {
	case err = <-errc:
		t.Fatalf("ReadFrom returned early: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	a.NoError(c.SetReadDeadline(time.Now().Add(-time.Millisecond)))
	select {
	case err = <-errc:
		a.ErrorIs(err, os.ErrDeadlineExceeded)
	case <-time.After(time.Second):
		t.Fatal("SetReadDeadline did not unblock ReadFrom")
	}

	a.NoError(c.SetDeadline(time.Now().Add(time.Second)))
	from := netip.MustParseAddrPort("192.0.2.1:9")
	to := c.LocalAddr().(*net.UDPAddr).AddrPort()
	n.Inject(from, to, []byte("ok"))
	got, _ := readFrom(t, c)
	a.Equal([]byte("ok"), got)
}

func TestCloseReadReturnsErrClosed(t *testing.T) {
	a := require.New(t)
	n := New()
	c := listen(t, n)
	to := c.LocalAddr().(*net.UDPAddr).AddrPort()
	n.Inject(netip.MustParseAddrPort("192.0.2.2:1"), to, []byte("x"))
	a.NoError(c.Close())
	_, _, err := c.ReadFrom(make([]byte, 8))
	a.ErrorIs(err, net.ErrClosed)
	_, err = c.WriteTo([]byte("y"), c.LocalAddr())
	a.ErrorIs(err, net.ErrClosed)

	c = listen(t, n)
	errc := make(chan error, 1)
	a.NoError(c.SetReadDeadline(time.Now().Add(2 * time.Second)))
	go func() {
		_, _, rerr := c.ReadFrom(make([]byte, 8))
		errc <- rerr
	}()
	select {
	case err = <-errc:
		t.Fatalf("ReadFrom returned early: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	a.NoError(c.Close())
	select {
	case err = <-errc:
		a.ErrorIs(err, net.ErrClosed)
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock ReadFrom")
	}
}

func TestWriteDeadline(t *testing.T) {
	a := require.New(t)
	n := New()
	c := listen(t, n)

	a.NoError(c.SetWriteDeadline(time.Now().Add(-time.Millisecond)))
	_, err := c.WriteTo([]byte("x"), c.LocalAddr())
	a.ErrorIs(err, os.ErrDeadlineExceeded)

	a.NoError(c.SetReadDeadline(time.Now().Add(40 * time.Millisecond)))
	_, _, err = c.ReadFrom(make([]byte, 1))
	a.ErrorIs(err, os.ErrDeadlineExceeded)

	a.NoError(c.SetWriteDeadline(time.Time{}))
	nw, err := c.WriteTo([]byte("x"), c.LocalAddr())
	a.NoError(err)
	a.Equal(1, nw)
	got, _ := readFrom(t, c)
	a.Equal([]byte("x"), got)
}

func TestQueueDropsWhenFull(t *testing.T) {
	a := require.New(t)
	a.Equal(256, queueCap)
	n := New()
	c := listen(t, n)
	to := c.LocalAddr().(*net.UDPAddr).AddrPort()
	from := netip.MustParseAddrPort("192.0.2.3:1")
	for i := range 257 {
		n.Inject(from, to, []byte{byte(i)})
	}

	for i := range 256 {
		a.NoError(c.SetReadDeadline(time.Now().Add(time.Second)))
		buf := make([]byte, 1)
		nr, _, err := c.ReadFrom(buf)
		a.NoError(err)
		a.Equal(1, nr)
		a.Equal(byte(i), buf[0])
	}
	a.NoError(c.SetReadDeadline(time.Now().Add(40 * time.Millisecond)))
	_, _, err := c.ReadFrom(make([]byte, 1))
	a.ErrorIs(err, os.ErrDeadlineExceeded)
}

func listen(t *testing.T, n *Net) net.PacketConn {
	t.Helper()
	a := require.New(t)
	c, err := n.Listen("127.0.0.1:0")
	a.NoError(err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func readFrom(t *testing.T, c net.PacketConn) ([]byte, net.Addr) {
	t.Helper()
	a := require.New(t)
	a.NoError(c.SetReadDeadline(time.Now().Add(time.Second)))
	buf := make([]byte, 2048)
	nr, addr, err := c.ReadFrom(buf)
	a.NoError(err)
	out := append([]byte(nil), buf[:nr]...)
	return out, addr
}
