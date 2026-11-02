package udppath

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// readStep is one result of scriptConn.ReadFrom.
type readStep struct {
	from net.Addr
	err  error
	data []byte
}

// scriptConn returns the steps it is fed, then net.ErrClosed once steps is
// closed. Only ReadFrom is used.
type scriptConn struct {
	net.PacketConn
	steps chan readStep
}

func (s *scriptConn) ReadFrom(b []byte) (int, net.Addr, error) {
	step, ok := <-s.steps
	if !ok {
		return 0, nil, net.ErrClosed
	}
	if step.err != nil {
		return 0, nil, step.err
	}
	return copy(b, step.data), step.from, nil
}

// recorder is a dispatcher that keeps what it is handed.
type recorder struct {
	got    [][]byte
	mu     sync.Mutex
	closed bool
}

func (r *recorder) handle(_ netip.AddrPort, pkt []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, append([]byte(nil), pkt...))
}

func (r *recorder) socketClosed() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
}

func (r *recorder) result() ([][]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.got, r.closed
}

// rawData is a DATA that passes validPacket, with marker as its counter.
func rawData(marker byte, size int) []byte {
	b := make([]byte, size)
	putHeader(b, typeData)
	binary.BigEndian.PutUint32(b[4:], 1)
	binary.BigEndian.PutUint64(b[sealedCtr:], uint64(marker))
	return b
}

var peer = net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.1:9"))

// runReader feeds steps to a reader, waits for it to end, and returns the
// reader and what its dispatcher got.
func runReader(
	t *testing.T, steps []readStep, configure func(*reader),
) (*reader, *recorder) {
	t.Helper()
	ch := make(chan readStep, len(steps))
	for _, s := range steps {
		ch <- s
	}
	close(ch)
	rec := &recorder{}
	r := newReader(&scriptConn{steps: ch}, rec, &counters{})
	if configure != nil {
		configure(r)
	}
	go r.run()
	select {
	case <-r.done:
	case <-time.After(5 * time.Second):
		require.New(t).FailNow("reader did not end")
	}
	return r, rec
}

func TestReaderTransientErrors(t *testing.T) {
	a := require.New(t)
	r, rec := runReader(t, []readStep{
		{data: rawData(1, 40), from: peer},
		{err: io.ErrShortBuffer},
		{err: syscall.EMSGSIZE},
		{err: os.ErrDeadlineExceeded},
		{err: syscall.ECONNREFUSED},
		{data: rawData(2, 40), from: peer},
	}, nil)
	got, closed := rec.result()
	a.Len(got, 2)
	a.Equal(byte(1), got[0][sealedCtr+7])
	a.Equal(byte(2), got[1][sealedCtr+7])
	a.True(closed, "net.ErrClosed reaches the dispatcher")
	a.Equal(uint64(4), r.stats.ReadErrors.Load())
}

func TestReaderBackoff(t *testing.T) {
	a := require.New(t)
	steps := make([]readStep, 0, 102)
	for range 100 {
		steps = append(steps, readStep{err: syscall.EMSGSIZE})
	}
	steps = append(steps, readStep{data: rawData(1, 40), from: peer})
	steps = append(steps, readStep{err: syscall.EMSGSIZE})
	var waits []time.Duration
	r, rec := runReader(t, steps, func(r *reader) {
		r.pause = func(_ <-chan struct{}, d time.Duration) bool {
			waits = append(waits, d)
			return true
		}
	})
	got, _ := rec.result()
	a.Len(got, 1, "traffic resumes after the errors")
	a.Equal(uint64(101), r.stats.ReadErrors.Load())
	a.Len(waits, 100-maxReadErrors+1, "a datagram resets the run")
	a.Equal(minErrBackoff, waits[0])
	a.Equal(2*minErrBackoff, waits[1])
	a.Equal(maxErrBackoff, waits[len(waits)-1])
	for i := 1; i < len(waits); i++ {
		a.LessOrEqual(waits[i], maxErrBackoff)
		a.GreaterOrEqual(waits[i], waits[i-1])
	}
}

func TestReaderHaltSkipsSocketClosed(t *testing.T) {
	a := require.New(t)
	ch := make(chan readStep)
	rec := &recorder{}
	r := newReader(&scriptConn{steps: ch}, rec, &counters{})
	go r.run()
	r.halt()
	close(ch)
	<-r.done
	_, closed := rec.result()
	a.False(closed)
}

func TestReaderSortsDatagrams(t *testing.T) {
	a := require.New(t)
	r, rec := runReader(t, []readStep{
		{data: []byte{0x00}, from: peer},
		{data: nil, from: peer},
		{data: []byte("KBRK0001"), from: peer},
		{data: rawData(1, 1501), from: peer},
		{data: rawData(2, 65_000), from: peer},
		{data: rawData(3, 40), from: &net.IPAddr{IP: net.IPv4(192, 0, 2, 1)}},
		{data: []byte{0x07, Version, 0, 0, 0, 0, 0, 1}, from: peer},
		{data: rawData(4, MaxDatagram), from: peer},
	}, nil)
	got, _ := rec.result()
	a.Len(got, 1)
	a.Equal(byte(4), got[0][sealedCtr+7])
	a.Equal(uint64(2), r.stats.Kick.Load())
	a.Equal(uint64(1), r.stats.Foreign.Load())
	a.Equal(uint64(4), r.stats.Malformed.Load())
}
