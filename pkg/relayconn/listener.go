package relayconn

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/relayconn/pb"
)

type RelayListener struct {
	ctx       context.Context
	channel   *exchange.Channel
	sessions  map[string]*RelayConn
	accept    chan *RelayConn
	cancel    context.CancelFunc
	closeFn   func()
	selfKey   []byte
	channelMu sync.Mutex
	mu        sync.Mutex
}

func ListenRelay(
	ctx context.Context, relayAddr string, selfKey []byte,
) (*RelayListener, error) {
	ws, _, err := websocket.Dial(ctx, fmt.Sprintf("ws://%s/ws", relayAddr), nil)
	if err != nil {
		return nil, fmt.Errorf("relay ws dial: %w", err)
	}

	adapter := &wsAdapter{conn: ws, ctx: ctx}
	ch, err := exchange.Initiate(adapter)
	if err != nil {
		ws.Close(websocket.StatusNormalClosure, "exchange failed")
		return nil, fmt.Errorf("hpke initiate: %w", err)
	}

	identityFrame := &pb.Frame{
		Kind: &pb.Frame_Identity{
			Identity: &pb.Identity{Key: selfKey},
		},
	}
	identityBytes, _ := proto.Marshal(identityFrame)
	if err := ch.WriteBytes(identityBytes); err != nil {
		ch.Close()
		return nil, fmt.Errorf("send identity: %w", err)
	}

	relayBytes, err := ch.ReadBytes()
	if err != nil {
		ch.Close()
		return nil, fmt.Errorf("read relay identity: %w", err)
	}
	var relayFrame pb.Frame
	if err := proto.Unmarshal(relayBytes, &relayFrame); err != nil {
		ch.Close()
		return nil, fmt.Errorf("unmarshal relay identity: %w", err)
	}
	_ = relayFrame.GetIdentity().GetKey()

	ctx, cancel := context.WithCancel(ctx)
	l := &RelayListener{
		channel:  ch,
		selfKey:  selfKey,
		sessions: make(map[string]*RelayConn),
		accept:   make(chan *RelayConn, 1),
		ctx:      ctx,
		cancel:   cancel,
		closeFn:  func() { ch.Close() },
	}

	go l.readPump()
	return l, nil
}

func (l *RelayListener) Accept() (kamune.Conn, error) {
	select {
	case rc := <-l.accept:
		return rc, nil
	case <-l.ctx.Done():
		return nil, net.ErrClosed
	}
}

func (l *RelayListener) Close() error {
	l.cancel()
	if l.closeFn != nil {
		l.closeFn()
	}
	return nil
}

func (l *RelayListener) readPump() {
	defer l.cancel()
	for {
		data, err := l.channel.ReadBytes()
		if err != nil {
			return
		}
		var frame pb.Frame
		if err := proto.Unmarshal(data, &frame); err != nil {
			slog.Error("relayconn: unmarshal frame", slog.Any("error", err))
			continue
		}
		switch v := frame.Kind.(type) {
		case *pb.Frame_Msg:
			l.deliver(v.Msg)
		case *pb.Frame_Ping:
			pong := &pb.Frame{Kind: &pb.Frame_Pong{Pong: &pb.Pong{}}}
			b, _ := proto.Marshal(pong)
			l.channelMu.Lock()
			l.channel.WriteBytes(b)
			l.channelMu.Unlock()
		case *pb.Frame_Pong, *pb.Frame_Ack, *pb.Frame_Identity:
		}
	}
}

func (l *RelayListener) deliver(msg *pb.Message) {
	data := msg.GetData()
	sessionID := msg.GetSessionId()

	l.mu.Lock()
	defer l.mu.Unlock()

	if rc, ok := l.sessions[sessionID]; ok {
		rc.pushData(data)
		return
	}

	senderKey := msg.GetSender()
	sid := sessionID
	rc := newRelayConn(l.ctx, l.channel, senderKey, sid, &l.channelMu)
	rc.closeFn = func() {
		l.mu.Lock()
		delete(l.sessions, sid)
		l.mu.Unlock()
	}
	l.sessions[sid] = rc
	rc.pushData(data)

	select {
	case l.accept <- rc:
	default:
		slog.Warn("relayconn: accept channel full, dropping session",
			slog.String("session_id", sid))
		delete(l.sessions, sid)
	}
}
