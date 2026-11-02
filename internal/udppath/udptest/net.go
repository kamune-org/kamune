// Package udptest is an in-memory UDP network for tests.
// It does not use the host network.
package udptest

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"
)

// queueCap is 256, the handshake queue size. A conn drops a
// datagram once its queue already holds that many. The drop is
// only on this test double: WriteTo still reports a full write,
// and the sender is not told.
const queueCap = 256

// Net delivers datagrams between conns that Listen on it.
type Net struct {
	conns  map[netip.AddrPort]*packetConn
	filter func(from, to netip.AddrPort, pkt []byte) int
	mu     sync.Mutex
	next   uint16
}

// packetConn is one bound address on a Net.
// queue is after the other pointer fields so its length and cap
// stay outside the GC pointer prefix.
type packetConn struct {
	readDL  time.Time
	writeDL time.Time
	addr    netip.AddrPort
	parent  *Net
	wake    chan struct{}
	queue   []datagram
	mu      sync.Mutex
	closed  bool
}

// datagram is one queued copy. addr is the source.
type datagram struct {
	addr *net.UDPAddr
	data []byte
}

// New returns an empty network.
func New() *Net {
	return &Net{
		conns: make(map[netip.AddrPort]*packetConn),
		next:  1,
	}
}

// Listen binds addr. "127.0.0.1:0" keeps that IP and picks a free
// port. The conn's network name is "udp". An IPv4-in-IPv6 address
// binds its IPv4 form.
func (n *Net) Listen(addr string) (net.PacketConn, error) {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, opErr("listen", nil, nil, err)
	}
	ap = unmap(ap)
	n.mu.Lock()
	defer n.mu.Unlock()
	if ap.Port() == 0 {
		picked, ok := n.freePort(ap.Addr())
		if !ok {
			err = errors.New("no free port")
			return nil, opErr("listen", nil, nil, err)
		}
		ap = picked
	} else if _, used := n.conns[ap]; used {
		ua := net.UDPAddrFromAddrPort(ap)
		err = errors.New("address already in use")
		return nil, opErr("listen", nil, ua, err)
	}
	c := newPacketConn(n, ap)
	n.conns[ap] = c
	return c, nil
}

// freePort returns an unused port for ip. The caller holds n.mu.
func (n *Net) freePort(ip netip.Addr) (netip.AddrPort, bool) {
	if n.next == 0 {
		n.next = 1
	}
	start := n.next
	for {
		port := n.next
		n.next++
		if n.next == 0 {
			n.next = 1
		}
		ap := netip.AddrPortFrom(ip, port)
		if _, used := n.conns[ap]; !used {
			return ap, true
		}
		if n.next == start {
			return netip.AddrPort{}, false
		}
	}
}

// Inject queues a copy of pkt at to, from an address with no conn.
// A missing listener or a full queue drops that copy. Both
// addresses lose any IPv4-in-IPv6 mapping, as WriteTo's do.
func (n *Net) Inject(from, to netip.AddrPort, pkt []byte) {
	n.deliver(unmap(from), unmap(to), pkt)
}

// SetFilter installs fn. fn returns how many copies to queue.
// Zero drops the datagram and two queues a duplicate. Nil fn
// queues one copy. fn runs on the WriteTo or Inject caller and
// must not block in ReadFrom: the copy is queued after fn returns.
func (n *Net) SetFilter(
	fn func(from, to netip.AddrPort, pkt []byte) int,
) {
	n.mu.Lock()
	n.filter = fn
	n.mu.Unlock()
}

// deliver copies pkt, asks the filter, and queues that many copies.
func (n *Net) deliver(from, to netip.AddrPort, pkt []byte) {
	pkt = cloneBytes(pkt)
	n.mu.Lock()
	fn := n.filter
	n.mu.Unlock()
	copies := 1
	if fn != nil {
		copies = fn(from, to, pkt)
	}
	if copies < 1 {
		return
	}
	n.mu.Lock()
	dst := n.conns[to]
	n.mu.Unlock()
	if dst == nil {
		return
	}
	dst.enqueue(from, pkt, copies)
}

func newPacketConn(parent *Net, addr netip.AddrPort) *packetConn {
	return &packetConn{
		parent: parent,
		addr:   addr,
		wake:   make(chan struct{}),
	}
}

func (c *packetConn) enqueue(
	from netip.AddrPort, pkt []byte, copies int,
) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	queued := false
	for range copies {
		if len(c.queue) >= queueCap {
			break
		}
		d := datagram{
			data: cloneBytes(pkt),
			addr: net.UDPAddrFromAddrPort(from),
		}
		c.queue = append(c.queue, d)
		queued = true
	}
	if queued {
		c.notifyLocked()
	}
}

// notifyLocked wakes ReadFrom. The closed channel wakes a waiter
// that already copied it; the new channel is the next wait.
// The caller holds c.mu.
func (c *packetConn) notifyLocked() {
	close(c.wake)
	c.wake = make(chan struct{})
}

// ReadFrom returns one datagram. An expired read deadline fails
// the call before a queued datagram is consumed. After Close the
// error is net.ErrClosed.
func (c *packetConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return 0, nil, net.ErrClosed
		}
		if expired(c.readDL) {
			c.mu.Unlock()
			return 0, nil, os.ErrDeadlineExceeded
		}
		if len(c.queue) > 0 {
			d := c.queue[0]
			c.queue[0] = datagram{}
			c.queue = c.queue[1:]
			c.mu.Unlock()
			n := copy(p, d.data)
			return n, d.addr, nil
		}
		dl := c.readDL
		wake := c.wake
		c.mu.Unlock()

		timer, timed := deadlineTimer(dl)
		select {
		case <-wake:
			stopTimer(timer)
		case <-timed:
		}
	}
}

// WriteTo copies p and queues it for the conn at addr. A full
// queue drops the copy. The write still counts as complete.
func (c *packetConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	closed := c.closed
	dl := c.writeDL
	c.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	if expired(dl) {
		return 0, os.ErrDeadlineExceeded
	}
	ap, err := udpAddrPort(addr)
	if err != nil {
		src := c.LocalAddr()
		return 0, opErr("write", src, addr, err)
	}
	c.parent.deliver(c.addr, ap, p)
	return len(p), nil
}

// Close drops the queue and unblocks ReadFrom. A later ReadFrom
// returns net.ErrClosed. A second Close returns nil.
func (c *packetConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.queue = nil
	c.notifyLocked()
	c.mu.Unlock()
	c.parent.remove(c)
	return nil
}

func (c *packetConn) LocalAddr() net.Addr {
	return net.UDPAddrFromAddrPort(c.addr)
}

func (c *packetConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.readDL = t
	c.writeDL = t
	c.notifyLocked()
	return nil
}

func (c *packetConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.readDL = t
	c.notifyLocked()
	return nil
}

func (c *packetConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.writeDL = t
	return nil
}

func (n *Net) remove(c *packetConn) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.conns[c.addr] == c {
		delete(n.conns, c.addr)
	}
}

// udpAddrPort converts addr. net.ResolveUDPAddr and net.ParseIP give
// IPv4 in its 16-byte form, which AddrPort maps into IPv6; unmapping
// it reaches the conn bound to the IPv4 address, as a socket does.
func udpAddrPort(addr net.Addr) (netip.AddrPort, error) {
	ua, ok := addr.(*net.UDPAddr)
	if !ok || ua == nil {
		return netip.AddrPort{}, errors.New("not a UDP address")
	}
	if ua.Port < 0 || ua.Port > 65535 {
		return netip.AddrPort{}, errors.New("invalid port")
	}
	ap := ua.AddrPort()
	if !ap.IsValid() {
		return netip.AddrPort{}, errors.New("invalid IP")
	}
	return unmap(ap), nil
}

// unmap removes an IPv4-in-IPv6 mapping from ap.
func unmap(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

func opErr(op string, src, addr net.Addr, err error) error {
	return &net.OpError{
		Op:     op,
		Net:    "udp",
		Source: src,
		Addr:   addr,
		Err:    err,
	}
}

func deadlineTimer(dl time.Time) (*time.Timer, <-chan time.Time) {
	if dl.IsZero() {
		return nil, nil
	}
	timer := time.NewTimer(time.Until(dl))
	return timer, timer.C
}

func stopTimer(timer *time.Timer) {
	if timer != nil {
		timer.Stop()
	}
}

func expired(t time.Time) bool {
	return !t.IsZero() && !time.Now().Before(t)
}

func cloneBytes(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

var _ net.PacketConn = (*packetConn)(nil)
