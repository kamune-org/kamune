package relayconn

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"sync"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/kamune-org/kamune"
)

// RelayListener implements [kamune.Listener] over a relay WebSocket. It
// accepts incoming sessions demultiplexed by session_id from a single
// WebSocket connection to the relay.
type RelayListener struct {
	ws       *websocket.Conn
	selfKey  []byte
	sessions map[string]*RelayConn
	accept   chan *RelayConn

	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
}

// ListenRelay connects to the relay as the given public key and returns a
// [RelayListener] that accepts incoming sessions addressed to this key.
func ListenRelay(ctx context.Context, relayAddr string, selfKey []byte) (*RelayListener, error) {
	keyB64 := base64.RawURLEncoding.EncodeToString(selfKey)
	u := fmt.Sprintf("ws://%s/ws?key=%s", relayAddr, keyB64)

	ws, _, err := websocket.Dial(ctx, u, nil)
	if err != nil {
		return nil, fmt.Errorf("relay ws dial: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	l := &RelayListener{
		ws:       ws,
		selfKey:  selfKey,
		sessions: make(map[string]*RelayConn),
		accept:   make(chan *RelayConn),
		ctx:      ctx,
		cancel:   cancel,
	}

	go l.readPump()
	return l, nil
}

func (l *RelayListener) Accept() (kamune.Conn, error) {
	select {
	case rc := <-l.accept:
		return rc, nil
	case <-l.ctx.Done():
		return nil, kamune.ErrClosedServer
	}
}

func (l *RelayListener) Close() error {
	l.cancel()
	return l.ws.Close(websocket.StatusNormalClosure, "listener closed")
}

func (l *RelayListener) readPump() {
	defer l.cancel()

	for {
		var msg relayMessage
		if err := wsjson.Read(l.ctx, l.ws, &msg); err != nil {
			slog.Error("relay ws read", slog.Any("error", err))
			return
		}

		switch msg.Type {
		case "connected", "pong":
			continue
		case "message":
			l.deliver(msg)
		case "message_ack", "message_queued":
			continue
		case "error":
			continue
		default:
			slog.Warn("unknown relay message type", slog.String("type", msg.Type))
		}
	}
}

func (l *RelayListener) deliver(msg relayMessage) {
	senderRaw, err := base64.RawURLEncoding.DecodeString(msg.Sender)
	if err != nil {
		slog.Error("decode relay sender", slog.Any("error", err))
		return
	}

	data, err := base64.RawURLEncoding.DecodeString(msg.Data)
	if err != nil {
		slog.Error("decode relay data", slog.Any("error", err))
		return
	}

	l.mu.Lock()

	if rc, ok := l.sessions[msg.SessionID]; ok {
		l.mu.Unlock()
		rc.pushData(data)
		return
	}

	sid := msg.SessionID
	rc := newRelayConn(l.ctx, l.ws, senderRaw, sid)
	l.sessions[sid] = rc
	rc.pushData(data)
	l.mu.Unlock()

	l.accept <- rc
}
