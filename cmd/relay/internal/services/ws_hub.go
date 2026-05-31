package services

import (
	"context"
	"encoding/base64"
	"log/slog"
	"sync"

	"github.com/hossein1376/grape/slogger"

	"github.com/kamune-org/kamune/cmd/relay/internal/model"
	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/relayconn/pb"
	"google.golang.org/protobuf/proto"
)

type wsConn struct {
	ch     *exchange.Channel
	cancel context.CancelFunc
}

type Hub struct {
	mu    sync.RWMutex
	conns map[model.PublicKey]*wsConn
}

func NewHub() *Hub {
	return &Hub{
		conns: make(map[model.PublicKey]*wsConn),
	}
}

func (h *Hub) Register(
	key model.PublicKey, ch *exchange.Channel, cancel context.CancelFunc,
) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if old, ok := h.conns[key]; ok {
		slog.Debug(
			"ws_hub: replacing existing connection", slogger.String("peer", key),
		)
		old.cancel()
		_ = old.ch.Close()
	}

	h.conns[key] = &wsConn{
		ch:     ch,
		cancel: cancel,
	}

	slog.Info("ws_hub: peer connected", slogger.String("peer", key))
}

func (h *Hub) Unregister(key model.PublicKey) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if wc, ok := h.conns[key]; ok {
		wc.cancel()
		_ = wc.ch.Close()
		delete(h.conns, key)
		slog.Info("ws_hub: peer disconnected", slogger.String("peer", key))
	}
}

func (h *Hub) Deliver(
	ctx context.Context,
	sender, receiver model.PublicKey,
	sessionID string,
	data []byte,
) bool {
	h.mu.RLock()
	wc, ok := h.conns[receiver]
	h.mu.RUnlock()

	if !ok {
		return false
	}

	senderRaw, err := base64.RawURLEncoding.DecodeString(string(sender))
	if err != nil {
		slog.Debug("ws_hub: decode sender", slogger.Err("err", err))
		return false
	}

	frame := &pb.Frame{
		Kind: &pb.Frame_Msg{
			Msg: &pb.Message{
				Sender:    senderRaw,
				SessionId: sessionID,
				Data:      data,
			},
		},
	}
	b, err := proto.Marshal(frame)
	if err != nil {
		return false
	}

	if err := wc.ch.WriteBytes(b); err != nil {
		slog.Debug(
			"ws_hub: delivery failed, removing peer",
			slogger.String("peer", sender),
			slogger.Err("err", err),
		)
		h.Unregister(receiver)
		return false
	}

	slog.Debug(
		"ws_hub: message delivered via WS", slogger.String("peer", receiver),
	)
	return true
}

func (h *Hub) IsConnected(key model.PublicKey) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	_, ok := h.conns[key]
	return ok
}

func (h *Hub) ConnectedCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.conns)
}

func (h *Hub) ReadPump(
	ctx context.Context,
	key model.PublicKey,
	ch *exchange.Channel,
	handler func(ctx context.Context, msg *pb.Message) error,
) {
	for {
		data, err := ch.ReadBytes()
		if err != nil {
			if ctx.Err() != nil {
				slog.Debug(
					"ws_hub: read pump context cancelled",
					slogger.String("peer", key),
				)
			} else {
				slog.Debug(
					"ws_hub: read pump error",
					slogger.String("peer", key),
					slogger.Err("err", err),
				)
			}
			return
		}

		var frame pb.Frame
		if err := proto.Unmarshal(data, &frame); err != nil {
			slog.Debug(
				"ws_hub: invalid frame from peer",
				slogger.String("peer", key),
				slogger.Err("err", err),
			)
			continue
		}

		switch v := frame.Kind.(type) {
		case *pb.Frame_Msg:
			if err := handler(ctx, v.Msg); err != nil {
				slog.Debug(
					"ws_hub: handler error",
					slogger.String("peer", key),
					slogger.Err("err", err),
				)
			}
		case *pb.Frame_Ping:
			pong := &pb.Frame{Kind: &pb.Frame_Pong{Pong: &pb.Pong{}}}
			b, _ := proto.Marshal(pong)
			ch.WriteBytes(b)
		}
	}
}
