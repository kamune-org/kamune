package relayconn

import (
	"context"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/relayconn/pb"
)

const (
	// maxBufferedFrames is the most received frames a RelayConn holds
	// before its reader stops pulling frames from the relay.
	maxBufferedFrames = 1024
	// maxBufferedBytes is the most payload bytes a RelayConn holds
	// before its reader stops pulling frames from the relay. An empty
	// buffer always takes one frame, whatever its size.
	maxBufferedBytes = 4 << 20
)

// RelayConn implements Conn for relay-mediated connections. It buffers
// incoming data from a readPump goroutine and exposes ReadBytes/WriteBytes
// for the kamune protocol. Deadline support uses a timer+channel pattern
// to unblock ReadBytes on timeout or cancellation, and SetDeadline wakes
// a blocked ReadBytes so that it applies the new deadline, as with
// net.Conn.
//
// The receive buffer is bounded by maxBufferedFrames and
// maxBufferedBytes. When it is full the reader blocks until ReadBytes
// drains it, so a peer or relay that sends faster than the consumer
// reads is pushed back through the transport instead of growing memory.
type RelayConn struct {
	deadline time.Time
	ctx      context.Context
	recv     chan struct{}
	space    chan struct{}
	// deadlineSet is closed and replaced, under deadlineMu, each time
	// SetDeadline runs.
	deadlineSet chan struct{}
	channel     *exchange.Channel
	channelMu   *sync.Mutex
	cancel      context.CancelFunc
	closeFn     func()
	buf         [][]byte
	bufBytes    int
	bufMu       sync.Mutex
	deadlineMu  sync.Mutex
	closeOnce   sync.Once
	// closed is set under channelMu once Close has closed the channel.
	closed     bool
	ttl        time.Duration
	sessionTTL time.Duration
}

func (c *RelayConn) TTL() time.Duration        { return c.ttl }
func (c *RelayConn) SessionTTL() time.Duration { return c.sessionTTL }

func newRelayConn(
	ctx context.Context, ch *exchange.Channel, channelMu *sync.Mutex,
) *RelayConn {
	ctx, cancel := context.WithCancel(ctx)
	return &RelayConn{
		recv:        make(chan struct{}, 1),
		space:       make(chan struct{}, 1),
		deadlineSet: make(chan struct{}),
		channel:     ch,
		channelMu:   channelMu,
		ctx:         ctx,
		cancel:      cancel,
	}
}

func (rc *RelayConn) ReadBytes() ([]byte, error) {
	for {
		rc.bufMu.Lock()
		if len(rc.buf) > 0 {
			data := rc.buf[0]
			rc.buf[0] = nil
			rc.buf = rc.buf[1:]
			rc.bufBytes -= len(data)
			rc.bufMu.Unlock()
			select {
			case rc.space <- struct{}{}:
			default:
			}
			return data, nil
		}
		rc.bufMu.Unlock()

		rc.deadlineMu.Lock()
		dl := rc.deadline
		deadlineSet := rc.deadlineSet
		rc.deadlineMu.Unlock()

		var timer *time.Timer
		var timeout <-chan time.Time
		if !dl.IsZero() {
			dur := time.Until(dl)
			if dur <= 0 {
				return nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(dur)
			timeout = timer.C
		}

		select {
		case <-rc.recv:
			if timer != nil {
				timer.Stop()
			}
		case <-timeout:
			return nil, os.ErrDeadlineExceeded
		case <-deadlineSet:
			// Apply the new deadline.
			if timer != nil {
				timer.Stop()
			}
		case <-rc.ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			// Return io.EOF so Transport.Receive() maps this to
			// ErrConnClosed rather than a generic error.
			return nil, io.EOF
		}
	}
}

// WriteBytes sends data to the peer. It returns net.ErrClosed once the
// connection is closed or its relay session has ended.
func (rc *RelayConn) WriteBytes(data []byte) error {
	frame := &pb.Frame{Kind: &pb.Frame_Msg{Msg: &pb.Message{Data: data}}}
	b, err := proto.Marshal(frame)
	if err != nil {
		return err
	}
	rc.channelMu.Lock()
	defer rc.channelMu.Unlock()
	if rc.closed || rc.ctx.Err() != nil {
		return net.ErrClosed
	}
	return rc.channel.WriteBytes(b)
}

// SetDeadline sets the read and write deadline. A zero t removes it. A
// ReadBytes call that is already blocked applies the new deadline at
// once: it returns os.ErrDeadlineExceeded if t has passed and stops
// waiting for an earlier deadline that t replaces.
func (rc *RelayConn) SetDeadline(t time.Time) error {
	if err := rc.channel.SetWriteDeadline(t); err != nil {
		return err
	}
	rc.deadlineMu.Lock()
	rc.deadline = t
	close(rc.deadlineSet)
	rc.deadlineSet = make(chan struct{})
	rc.deadlineMu.Unlock()
	return nil
}

// Close closes the connection. It is safe to call more than once; only
// the first call has an effect. No write is in progress once Close
// returns, and later writes return net.ErrClosed.
func (rc *RelayConn) Close() error {
	rc.closeOnce.Do(func() {
		rc.cancel()
		if rc.closeFn != nil {
			rc.closeFn()
		}
		// closeFn has closed the channel, so a WriteBytes that passed
		// its check before cancel fails or finishes now. Taking
		// channelMu waits for it.
		rc.channelMu.Lock()
		rc.closed = true
		rc.channelMu.Unlock()
	})
	return nil
}

// pushData appends data to the receive buffer. While the buffer is
// full it blocks until ReadBytes makes room. It returns false, dropping
// data, if the connection is closed first, including when it was
// already closed on entry.
func (rc *RelayConn) pushData(data []byte) bool {
	for {
		rc.bufMu.Lock()
		if rc.ctx.Err() != nil {
			rc.bufMu.Unlock()
			return false
		}
		if rc.hasRoomLocked(len(data)) {
			rc.buf = append(rc.buf, data)
			rc.bufBytes += len(data)
			rc.bufMu.Unlock()
			select {
			case rc.recv <- struct{}{}:
			default:
			}
			return true
		}
		rc.bufMu.Unlock()

		select {
		case <-rc.space:
		case <-rc.ctx.Done():
			return false
		}
	}
}

// hasRoomLocked reports whether a frame of n bytes fits in the receive
// buffer. The caller must hold bufMu.
func (rc *RelayConn) hasRoomLocked(n int) bool {
	if len(rc.buf) == 0 {
		return true
	}
	return len(rc.buf) < maxBufferedFrames &&
		rc.bufBytes+n <= maxBufferedBytes
}

// readPump continuously reads frames from the exchange channel and
// dispatches them: message frames are pushed into the read buffer,
// ping frames receive an automatic pong reply. While the buffer is full
// the pump stops reading. On read error or context cancellation the
// pump exits and cancels the context.
func (rc *RelayConn) readPump() {
	defer rc.cancel()
	for {
		data, err := rc.channel.ReadBytes()
		if err != nil {
			return
		}
		var frame pb.Frame
		if err := proto.Unmarshal(data, &frame); err != nil {
			continue
		}
		switch v := frame.Kind.(type) {
		case *pb.Frame_Msg:
			if !rc.pushData(v.Msg.GetData()) {
				return
			}
		case *pb.Frame_Ping:
			pong := &pb.Frame{Kind: &pb.Frame_Pong{Pong: &pb.Pong{}}}
			b, _ := proto.Marshal(pong)
			rc.channelMu.Lock()
			rc.channel.WriteBytes(b)
			rc.channelMu.Unlock()
		case *pb.Frame_Pong:
		}
	}
}
