package handlers

import (
	"context"
	"encoding/base64"
	"log/slog"
	"net/http"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/hossein1376/grape"

	"github.com/kamune-org/kamune/relay/internal/services"
)

// WebSocketHandler upgrades an HTTP request to a WebSocket connection and
// registers the peer in the hub for real-time bidirectional message relay.
//
// The client must provide its public key as a query parameter (?key=<base64>).
// Once connected, the server enters a read loop that processes incoming JSON
// messages via Service.HandleWSMessage.
//
// Supported inbound message types:
//
//   - "message": relay a message to another peer (fields: receiver, session_id, data)
//   - "ping":    keepalive; the server responds with {"type":"pong"}
//
// The server may push the following message types to the client at any time:
//
//   - "message":        an incoming message from another peer
//   - "message_ack":    confirmation that a relayed message was delivered
//   - "message_queued": the relayed message could not be delivered and was queued
//   - "pong":           response to a "ping"
//   - "error":          something went wrong processing a client message
func (h *Handler) WebSocketHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// --- Authenticate: extract & parse the peer's public key ----------------
	pubKeyEncoded := r.URL.Query().Get("key")
	if pubKeyEncoded == "" {
		grape.Respond(ctx, w, http.StatusBadRequest, grape.Map{
			"error": "key query parameter is required",
		})
		return
	}

	pubKeyRaw, err := base64.RawURLEncoding.DecodeString(pubKeyEncoded)
	if err != nil {
		grape.Respond(ctx, w, http.StatusBadRequest, grape.Map{
			"error": "invalid base64 public key",
		})
		return
	}

	pk, err := h.service.ParsePublicKeyFor(pubKeyRaw)
	if err != nil {
		grape.Respond(ctx, w, http.StatusBadRequest, grape.Map{
			"error": "invalid public key: " + err.Error(),
		})
		return
	}

	// --- Upgrade to WebSocket -----------------------------------------------
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// Allow any origin so CLI / native clients can connect without CORS.
		InsecureSkipVerify: true,
	})
	if err != nil {
		slog.Error("ws: failed to accept", slog.Any("err", err))
		return
	}

	// Apply the same per-message size limit as the REST queue endpoints.
	if maxSize := h.service.MaxMessageSize(); maxSize > 0 {
		conn.SetReadLimit(int64(maxSize))
	}

	// --- Register in the hub ------------------------------------------------
	hub := h.service.Hub()
	if hub == nil {
		_ = conn.Close(websocket.StatusInternalError, "websocket hub unavailable")
		return
	}

	connCtx, cancel := context.WithCancel(ctx)
	hub.Register(pk, conn, cancel)

	// Track metrics.
	if m := h.service.Metrics(); m != nil {
		m.IncWSConnections()
	}

	// Send a welcome message so the client knows the handshake succeeded.
	_ = wsjson.Write(connCtx, conn, services.WSMessage{
		Type: "connected",
	})

	slog.Info("ws: peer connected",
		slog.String("peer", pubKeyEncoded),
		slog.String("remote", clientIP(r)),
	)

	// --- Read pump (blocks until disconnect) --------------------------------
	hub.ReadPump(connCtx, pk, conn, func(msgCtx context.Context, msg services.WSMessage) error {
		if m := h.service.Metrics(); m != nil {
			m.IncWSMessagesIn()
		}
		err := h.service.HandleWSMessage(msgCtx, pk, conn, msg)
		if err == nil {
			if m := h.service.Metrics(); m != nil {
				m.IncWSMessagesOut()
			}
		}
		return err
	})

	// --- Cleanup after disconnect -------------------------------------------
	hub.Unregister(pk)
	if m := h.service.Metrics(); m != nil {
		m.DecWSConnections()
	}

	slog.Info("ws: peer disconnected",
		slog.String("peer", pubKeyEncoded),
	)
}
