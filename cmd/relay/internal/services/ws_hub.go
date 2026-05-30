package services

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/hossein1376/grape/slogger"

	"github.com/kamune-org/kamune/cmd/relay/internal/model"
)

// WSMessage represents a JSON message sent over a WebSocket connection.
type WSMessage struct {
	Type      string          `json:"type"`
	Sender    model.PublicKey `json:"sender,omitempty"`
	Receiver  model.PublicKey `json:"receiver,omitempty"`
	SessionID string          `json:"session_id,omitempty"`
	Data      string          `json:"data,omitempty"`
	Error     string          `json:"error,omitempty"`
}

// wsConn wraps a WebSocket connection with its associated public key.
type wsConn struct {
	conn   *websocket.Conn
	cancel context.CancelFunc
}

// Hub manages active WebSocket connections keyed by the base64-encoded
// marshaled public key of each peer. It enables real-time message delivery
// to connected peers.
type Hub struct {
	mu    sync.RWMutex
	conns map[model.PublicKey]*wsConn // base64(pubkey) -> connection
}

// NewHub creates a new WebSocket hub.
func NewHub() *Hub {
	return &Hub{
		conns: make(map[model.PublicKey]*wsConn),
	}
}

// Register adds a WebSocket connection to the hub, associated with the given
// public key. If a previous connection exists for the same key it is closed
// before being replaced.
func (h *Hub) Register(
	key model.PublicKey, conn *websocket.Conn, cancel context.CancelFunc,
) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Close previous connection if it exists.
	if old, ok := h.conns[key]; ok {
		slog.Debug(
			"ws_hub: replacing existing connection", slogger.String("peer", key),
		)
		old.cancel()
		_ = old.conn.Close(websocket.StatusGoingAway, "replaced by new connection")
	}

	h.conns[key] = &wsConn{
		conn:   conn,
		cancel: cancel,
	}

	slog.Info("ws_hub: peer connected", slogger.String("peer", key))
}

// Unregister removes a WebSocket connection from the hub.
func (h *Hub) Unregister(key model.PublicKey) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if wc, ok := h.conns[key]; ok {
		wc.cancel()
		_ = wc.conn.Close(websocket.StatusNormalClosure, "unregistered")
		delete(h.conns, key)
		slog.Info("ws_hub: peer disconnected", slogger.String("peer", key))
	}
}

// Deliver attempts to send a message to the receiver over an active WebSocket
// connection. Returns true if the message was delivered, false if the receiver
// is not connected or the write failed.
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

	msg := WSMessage{
		Type:      "message",
		Sender:    sender,
		SessionID: sessionID,
		Data:      base64.RawURLEncoding.EncodeToString(data),
	}

	if err := wsjson.Write(ctx, wc.conn, msg); err != nil {
		slog.Debug(
			"ws_hub: delivery failed, removing peer",
			slogger.String("peer", sender),
			slogger.Err("err", err),
		)
		// Connection is broken; remove it.
		h.Unregister(receiver)
		return false
	}

	slog.Debug(
		"ws_hub: message delivered via WS", slogger.String("peer", receiver),
	)
	return true
}

// IsConnected returns whether a peer with the given public key has an active
// WebSocket connection.
func (h *Hub) IsConnected(key model.PublicKey) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	_, ok := h.conns[key]

	return ok
}

// ConnectedCount returns the number of active WebSocket connections.
func (h *Hub) ConnectedCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.conns)
}

// ReadPump reads messages from a WebSocket connection and processes them.
// It blocks until the connection is closed or the context is cancelled.
// The provided handler is called for each incoming message.
func (h *Hub) ReadPump(
	ctx context.Context,
	key model.PublicKey,
	conn *websocket.Conn,
	handler func(ctx context.Context, msg WSMessage) error,
) {
	for {
		_, raw, err := conn.Read(ctx)
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

		var msg WSMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			slog.Debug(
				"ws_hub: invalid message from peer",
				slogger.String("peer", key),
				slogger.Err("err", err),
			)
			errMsg := WSMessage{
				Type:  "error",
				Error: fmt.Sprintf("invalid message format: %v", err),
			}
			_ = wsjson.Write(ctx, conn, errMsg)
			continue
		}

		if err := handler(ctx, msg); err != nil {
			slog.Debug(
				"ws_hub: handler error",
				slogger.String("peer", key),
				slog.String("type", msg.Type),
				slogger.Err("err", err),
			)
			errMsg := WSMessage{
				Type:  "error",
				Error: err.Error(),
			}
			_ = wsjson.Write(ctx, conn, errMsg)
		}
	}
}

// SendAck sends an acknowledgement message over the WebSocket connection.
func SendAck(ctx context.Context, conn *websocket.Conn, msgType string) error {
	return wsjson.Write(ctx, conn, WSMessage{
		Type: msgType + "_ack",
	})
}
