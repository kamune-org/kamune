package services

import (
	"context"
	"log/slog"
	"time"

	"github.com/kamune-org/kamune/cmd/relay/internal/ratelimit"
	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/relayconn/pb"
	"google.golang.org/protobuf/proto"
)

type Hub struct {
	sessions         *SessionManager
	password         string
	maxMsgSize       int
	rateLimiter      *ratelimit.RateLimiter
	handshakeTimeout time.Duration
}

func NewHub(
	sessions *SessionManager,
	password string,
	maxMsgSize int,
	rateLimiter *ratelimit.RateLimiter,
	handshakeTimeout time.Duration,
) *Hub {
	return &Hub{
		sessions:         sessions,
		password:         password,
		maxMsgSize:       maxMsgSize,
		rateLimiter:      rateLimiter,
		handshakeTimeout: handshakeTimeout,
	}
}

func (h *Hub) RateLimiter() *ratelimit.RateLimiter {
	return h.rateLimiter
}

func (h *Hub) HandshakeTimeout() time.Duration {
	return h.handshakeTimeout
}

func (h *Hub) TokenTTL() time.Duration {
	return h.sessions.TTL()
}

func (h *Hub) MaxMessageSize() int {
	return h.maxMsgSize
}

func (h *Hub) Password() string {
	return h.password
}

func (h *Hub) RegisterListener(ch *exchange.Channel) ([]byte, error) {
	return h.sessions.Create(ch)
}

func (h *Hub) RegisterDialer(ch *exchange.Channel, token []byte) error {
	return h.sessions.Join(token, ch)
}

func (h *Hub) ReadPump(ctx context.Context, ch *exchange.Channel, token []byte) {
	defer h.sessions.ClosePeerChannel(token, ch)

	cancelCh := make(chan struct{})
	defer close(cancelCh)

	go func() {
		select {
		case <-ctx.Done():
			ch.Close()
		case <-cancelCh:
		}
	}()

	for {
		data, err := ch.ReadBytes()
		if err != nil {
			slog.Debug("hub: read pump error", slog.Any("error", err))
			return
		}

		var frame pb.Frame
		if err := proto.Unmarshal(data, &frame); err != nil {
			slog.Debug("hub: invalid frame", slog.Any("error", err))
			continue
		}

		switch v := frame.Kind.(type) {
		case *pb.Frame_Msg:
			h.handleMessage(ch, token, v.Msg.GetData())
		case *pb.Frame_Ping:
			h.handlePing(ch)
		}
	}
}

func (h *Hub) handleMessage(sender *exchange.Channel, token []byte, data []byte) {
	recipient, err := h.sessions.Recipient(token, sender)
	if err != nil {
		slog.Debug("hub: no recipient", slog.Any("error", err))
		return
	}

	frame := &pb.Frame{
		Kind: &pb.Frame_Msg{
			Msg: &pb.Message{Data: data},
		},
	}
	b, err := proto.Marshal(frame)
	if err != nil {
		slog.Debug("hub: marshal message", slog.Any("error", err))
		return
	}

	if err := recipient.WriteBytes(b); err != nil {
		slog.Debug("hub: write to recipient failed", slog.Any("error", err))
		sender.Close()
		// ClosePeerChannel + Remove happen in ReadPump's defer once
		// sender's ReadPump exits from the channel close above.
	}
}

func (h *Hub) handlePing(ch *exchange.Channel) {
	pong := &pb.Frame{Kind: &pb.Frame_Pong{Pong: &pb.Pong{}}}
	b, _ := proto.Marshal(pong)
	if err := ch.WriteBytes(b); err != nil {
		slog.Debug("hub: write pong failed", slog.Any("error", err))
	}
}

func (h *Hub) Unregister(token []byte) {
	h.sessions.Remove(token)
}
