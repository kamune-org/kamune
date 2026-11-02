package udppath

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

// dispatcher handles what the socket reader accepts. Both run on the
// reader's goroutine.
type dispatcher interface {
	// handle gets a datagram of this layer that passed validPacket. pkt is
	// valid only during the call.
	handle(src netip.AddrPort, pkt []byte)
	// socketClosed runs once when the socket is closed under the reader.
	socketClosed()
}

// reader is the one goroutine that reads a socket. It never returns an
// error to kcp-go: every read error other than a closed socket is transient,
// and every datagram, of any size, is read whole and checked.
type reader struct {
	pc    net.PacketConn
	d     dispatcher
	stats *counters
	stop  chan struct{}
	done  chan struct{}
	// pause waits between reads after a run of errors. Tests replace it.
	pause    func(stop <-chan struct{}, d time.Duration) bool
	stopOnce sync.Once
}

func newReader(pc net.PacketConn, d dispatcher, stats *counters) *reader {
	return &reader{
		pc:    pc,
		d:     d,
		stats: stats,
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
		pause: pauseUntil,
	}
}

// halt makes the reader end at its next read error, without telling the
// dispatcher. The caller then closes the socket.
func (r *reader) halt() {
	r.stopOnce.Do(func() { close(r.stop) })
}

func (r *reader) halted() bool {
	select {
	case <-r.stop:
		return true
	default:
		return false
	}
}

func (r *reader) run() {
	defer close(r.done)
	buf := make([]byte, readBufSize)
	errs := 0
	var backoff time.Duration
	for {
		n, from, err := r.pc.ReadFrom(buf)
		if err != nil {
			if r.halted() {
				return
			}
			if errors.Is(err, net.ErrClosed) {
				r.d.socketClosed()
				return
			}
			r.stats.ReadErrors.Add(1)
			if errs++; errs >= maxReadErrors {
				backoff = nextBackoff(backoff)
				if !r.pause(r.stop, backoff) {
					return
				}
			}
			continue
		}
		errs, backoff = 0, 0
		pkt := buf[:n]
		switch classify(pkt) {
		case classKick:
			r.stats.Kick.Add(1)
			continue
		case classForeign:
			r.stats.Foreign.Add(1)
			continue
		case classOurs:
		}
		src, ok := udpSource(from)
		if !ok || !validPacket(pkt) {
			r.stats.Malformed.Add(1)
			continue
		}
		r.d.handle(src, pkt)
	}
}

// pauseUntil waits for d and reports true, or reports false once stop is
// closed.
func pauseUntil(stop <-chan struct{}, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-stop:
		return false
	}
}
