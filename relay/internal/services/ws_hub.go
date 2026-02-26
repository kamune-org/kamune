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

	"github.com/kamune-org/kamune/pkg/attest"
)

// WSMessage represents a JSON message sent over a WebSocket connection.
type WSMessage struct {
	Type      string `json:"type"`
	Sender    string `json:"sender,omitempty"`
	Receiver  string `json:"receiver,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	Data      string `json:"data,omitempty"`
	Error     string `json:"error,omitempty"`
}

// wsConn wraps a WebSocket connection with its associated public key.
type wsConn struct {
	conn      *websocket.Conn
	publicKey attest.PublicKey
	cancel    context.CancelFunc
}

// Hub manages active WebSocket connections keyed by the base64-encoded
// marshalled public key of each peer. It enables real-time message delivery
// to connected peers.
type Hub struct {
	mu    sync.RWMutex
	conns map[string]*wsConn // base64(pubkey) -> connection
}

// NewHub creates a new WebSocket hub.
func NewHub() *Hub {
	return &Hub{
		conns: make(map[string]*wsConn),
	}
}

// peerKey returns the canonical map key for a public key.
func peerKey(pk attest.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(pk.Marshal())
}

// Register adds a WebSocket connection to the hub, associated with the given
// public key. If a previous connection exists for the same key it is closed
// before being replaced.
func (h *Hub) Register(pk attest.PublicKey, conn *websocket.Conn, cancel context.CancelFunc) {
	key := peerKey(pk)

	h.mu.Lock()
	defer h.mu.Unlock()

	// Close previous connection if it exists.
	if old, ok := h.conns[key]; ok {
		slog.Debug("ws_hub: replacing existing connection", slog.String("peer", key))
		old.cancel()
		_ = old.conn.Close(websocket.StatusGoingAway, "replaced by new connection")
	}

	h.conns[key] = &wsConn{
		conn:      conn,
		publicKey: pk,
		cancel:    cancel,
	}

	slog.Info("ws_hub: peer connected", slog.String("peer", key))
}

// Unregister removes a WebSocket connection from the hub.
func (h *Hub) Unregister(pk attest.PublicKey) {
	key := peerKey(pk)

	h.mu.Lock()
	defer h.mu.Unlock()

	if wc, ok := h.conns[key]; ok {
		wc.cancel()
		_ = wc.conn.Close(websocket.StatusNormalClosure, "unregistered")
		delete(h.conns, key)
		slog.Info("ws_hub: peer disconnected", slog.String("peer", key))
	}
}

// Deliver attempts to send a message to the receiver over an active WebSocket
// connection. Returns true if the message was delivered, false if the receiver
// is not connected or the write failed.
func (h *Hub) Deliver(ctx context.Context, sender, receiver attest.PublicKey, sessionID string, data []byte) bool {
	key := peerKey(receiver)

	h.mu.RLock()
	wc, ok := h.conns[key]
	h.mu.RUnlock()

	if !ok {
		return false
	}

	msg := WSMessage{
		Type:      "message",
		Sender:    peerKey(sender),
		SessionID: sessionID,
		Data:      base64.RawURLEncoding.EncodeToString(data),
	}

	if err := wsjson.Write(ctx, wc.conn, msg); err != nil {
		slog.Debug("ws_hub: delivery failed, removing peer",
			slog.String("peer", key),
			slog.Any("err", err),
		)
		// Connection is broken; remove it.
		h.Unregister(receiver)
		return false
	}

	slog.Debug("ws_hub: message delivered via websocket", slog.String("peer", key))
	return true
}

// IsConnected returns whether a peer with the given public key has an active
// WebSocket connection.
func (h *Hub) IsConnected(pk attest.PublicKey) bool {
	key := peerKey(pk)

	h.mu.RLock()
	_, ok := h.conns[key]
	h.mu.RUnlock()

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
func (h *Hub) ReadPump(ctx context.Context, pk attest.PublicKey, conn *websocket.Conn, handler func(ctx context.Context, msg WSMessage) error) {
	key := peerKey(pk)
	for {
		_, raw, err := conn.Read(ctx)
		if err != nil {
			if ctx.Err() != nil {
				slog.Debug("ws_hub: read pump context cancelled", slog.String("peer", key))
			} else {
				slog.Debug("ws_hub: read pump error",
					slog.String("peer", key),
					slog.Any("err", err),
				)
			}
			return
		}

		var msg WSMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			slog.Debug("ws_hub: invalid message from peer",
				slog.String("peer", key),
				slog.Any("err", err),
			)
			errMsg := WSMessage{
				Type:  "error",
				Error: fmt.Sprintf("invalid message format: %v", err),
			}
			_ = wsjson.Write(ctx, conn, errMsg)
			continue
		}

		if err := handler(ctx, msg); err != nil {
			slog.Debug("ws_hub: handler error",
				slog.String("peer", key),
				slog.String("type", msg.Type),
				slog.Any("err", err),
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
