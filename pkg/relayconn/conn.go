package relayconn

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"

	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/relayconn/pb"
)

type RelayConn struct {
	sessionID string
	peerKey   []byte

	buf   [][]byte
	bufMu sync.Mutex
	recv  chan struct{}

	channel   *exchange.Channel
	channelMu *sync.Mutex

	ctx    context.Context
	cancel context.CancelFunc

	closeFn func()

	deadline   time.Time
	deadlineMu sync.Mutex
}

func newRelayConn(
	ctx context.Context,
	ch *exchange.Channel,
	peerKey []byte,
	sessionID string,
	channelMu *sync.Mutex,
) *RelayConn {
	ctx, cancel := context.WithCancel(ctx)
	return &RelayConn{
		sessionID: sessionID,
		peerKey:   peerKey,
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
			return nil, rc.ctx.Err()
		}
	}
}

func (rc *RelayConn) WriteBytes(data []byte) error {
	frame := &pb.Frame{
		Kind: &pb.Frame_Msg{
			Msg: &pb.Message{
				Receiver:  rc.peerKey,
				SessionId: rc.sessionID,
				Data:      data,
			},
		},
	}
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
		case *pb.Frame_Pong, *pb.Frame_Ack:
		}
	}
}

type wsAdapter struct {
	conn *websocket.Conn
	ctx  context.Context
}

func (w *wsAdapter) ReadBytes() ([]byte, error) {
	_, data, err := w.conn.Read(w.ctx)
	return data, err
}

func (w *wsAdapter) WriteBytes(data []byte) error {
	return w.conn.Write(w.ctx, websocket.MessageBinary, data)
}

func (w *wsAdapter) Close() error {
	return w.conn.Close(websocket.StatusNormalClosure, "closed")
}

func (w *wsAdapter) SetDeadline(time.Time) error { return nil }
