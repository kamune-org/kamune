package relayconn

import (
	"context"
	"io"
	"os"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/relayconn/pb"
)

// RelayConn implements Conn for relay-mediated connections. It buffers
// incoming data from a readPump goroutine and exposes ReadBytes/WriteBytes
// for the kamune protocol. Deadline support uses a timer+channel pattern
// to unblock ReadBytes on timeout or cancellation.
type RelayConn struct {
	deadline   time.Time
	ctx        context.Context
	recv       chan struct{}
	channel    *exchange.Channel
	channelMu  *sync.Mutex
	cancel     context.CancelFunc
	closeFn    func()
	buf        [][]byte
	bufMu      sync.Mutex
	deadlineMu sync.Mutex
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
		recv:      make(chan struct{}, 1),
		channel:   ch,
		channelMu: channelMu,
		ctx:       ctx,
		cancel:    cancel,
	}
}

func (rc *RelayConn) ReadBytes() ([]byte, error) {
	for {
		rc.bufMu.Lock()
		if len(rc.buf) > 0 {
			data := rc.buf[0]
			rc.buf = rc.buf[1:]
			rc.bufMu.Unlock()
			return data, nil
		}
		rc.bufMu.Unlock()

		rc.deadlineMu.Lock()
		dl := rc.deadline
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

func (rc *RelayConn) WriteBytes(data []byte) error {
	frame := &pb.Frame{Kind: &pb.Frame_Msg{Msg: &pb.Message{Data: data}}}
	b, err := proto.Marshal(frame)
	if err != nil {
		return err
	}
	rc.channelMu.Lock()
	defer rc.channelMu.Unlock()
	return rc.channel.WriteBytes(b)
}

func (rc *RelayConn) SetDeadline(t time.Time) error {
	rc.deadlineMu.Lock()
	rc.deadline = t
	rc.deadlineMu.Unlock()
	return nil
}

func (rc *RelayConn) Close() error {
	rc.cancel()
	if rc.closeFn != nil {
		rc.closeFn()
	}
	return nil
}

func (rc *RelayConn) pushData(data []byte) {
	rc.bufMu.Lock()
	rc.buf = append(rc.buf, data)
	rc.bufMu.Unlock()
	select {
	case rc.recv <- struct{}{}:
	default:
	}
}

// readPump continuously reads frames from the exchange channel and
// dispatches them: message frames are pushed into the read buffer,
// ping frames receive an automatic pong reply. On read error or
// context cancellation the pump exits and cancels the context.
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
			rc.pushData(v.Msg.GetData())
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
