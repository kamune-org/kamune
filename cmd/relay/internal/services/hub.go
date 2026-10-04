package services

import (
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

func (h *Hub) SessionTTL() time.Duration {
	return h.sessions.SessionTTL()
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

func (h *Hub) RegisterListenerWith(ch *exchange.Channel, token []byte) error {
	return h.sessions.CreateWith(ch, token)
}

func (h *Hub) RegisterDialer(ch *exchange.Channel, token []byte) error {
	return h.sessions.Join(token, ch)
}

func (h *Hub) ReadPump(ch *exchange.Channel, token []byte) {
	defer h.sessions.Leave(token, ch)

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

// handleMessage forwards one frame from sender to the other peer of its
// session, and drops it if that peer has not joined yet. It never drops a
// frame for a slow recipient: kamune treats a missing frame as fatal, so a
// drop would only end the session later and less clearly. The write runs
// on the sender's read pump, so a slow recipient holds up the sender's
// frames, pings included, and one that has not taken a frame within 15
// seconds ends the session for both peers.
func (h *Hub) handleMessage(sender *exchange.Channel, token []byte, data []byte) {
	// Recipient is looked up under sm.mu and the write happens after
	// the lock is released. This is intentional: holding the session
	// lock across a (potentially blocking) peer write would serialize
	// all forwarding in the relay on a single mutex. The lookup result
	// is a stable *Channel pointer; if the peer is closed concurrently,
	// the write fails and the error path closes the session.
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

	const writeTimeout = 15 * time.Second
	if err := recipient.WriteBytesWithin(b, writeTimeout); err != nil {
		slog.Debug("hub: write to recipient failed", slog.Any("error", err))
		// Close both peers so neither side blocks on a half-open
		// connection waiting for the other to discover the failure.
		// Channel.Close is idempotent.
		sender.Close()
		recipient.Close()
	}
}

func (h *Hub) handlePing(ch *exchange.Channel) {
	pong := &pb.Frame{Kind: &pb.Frame_Pong{Pong: &pb.Pong{}}}
	b, _ := proto.Marshal(pong)
	const writeTimeout = 15 * time.Second
	if err := ch.WriteBytesWithin(b, writeTimeout); err != nil {
		slog.Debug("hub: write pong failed", slog.Any("error", err))
		ch.Close()
	}
}

// Leave removes the session that ch belongs to and closes the other peer, in
// one step. See SessionManager.Leave.
func (h *Hub) Leave(token []byte, ch *exchange.Channel) {
	h.sessions.Leave(token, ch)
}
