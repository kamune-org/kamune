package services

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/kamune-org/kamune/pkg/attest"
)

// Hub returns the service's WebSocket hub, or nil if WebSocket support
// is not enabled.
func (s *Service) Hub() *Hub {
	return s.hub
}

// HandleWSMessage processes an incoming WebSocket message from the given
// sender. It supports the following message types:
//
//   - "message": relay a message to the receiver (direct via WS if connected,
//     otherwise enqueue).
//   - "ping": respond with a "pong" acknowledgement.
func (s *Service) HandleWSMessage(
	ctx context.Context,
	senderPK attest.PublicKey,
	conn *websocket.Conn,
	msg WSMessage,
) error {
	switch msg.Type {
	case "message":
		return s.handleWSRelay(ctx, senderPK, conn, msg)
	case "ping":
		return wsjson.Write(ctx, conn, WSMessage{Type: "pong"})
	default:
		return fmt.Errorf("unknown message type: %q", msg.Type)
	}
}

// handleWSRelay relays a message received over WebSocket to the intended
// receiver. It first tries WebSocket delivery (via the hub), then falls
// back to the queue.
func (s *Service) handleWSRelay(
	ctx context.Context,
	senderPK attest.PublicKey,
	conn *websocket.Conn,
	msg WSMessage,
) error {
	if msg.Receiver == "" || msg.SessionID == "" || msg.Data == "" {
		return fmt.Errorf("receiver, session_id and data are required")
	}

	// Decode receiver public key.
	receiverRaw, err := base64.RawURLEncoding.DecodeString(msg.Receiver)
	if err != nil {
		return fmt.Errorf("decoding receiver key: %w", err)
	}
	receiverPK, err := s.ParsePublicKeyFor(receiverRaw)
	if err != nil {
		return fmt.Errorf("parsing receiver key: %w", err)
	}

	// Decode payload.
	dataRaw, err := base64.RawURLEncoding.DecodeString(msg.Data)
	if err != nil {
		return fmt.Errorf("decoding data: %w", err)
	}

	// Try WebSocket delivery first.
	if s.hub != nil && s.hub.Deliver(ctx, senderPK, receiverPK, msg.SessionID, dataRaw) {
		slog.Debug("ws: delivered via hub",
			slog.String("receiver", msg.Receiver),
		)
		return wsjson.Write(ctx, conn, WSMessage{
			Type:      "message_ack",
			SessionID: msg.SessionID,
		})
	}

	// Try HTTP direct delivery to registered addresses, then fall back to queue.
	delivered, err := s.Convey(senderPK, receiverPK, msg.SessionID, dataRaw)
	if err != nil {
		return fmt.Errorf("convey: %w", err)
	}

	ackType := "message_queued"
	if delivered {
		ackType = "message_ack"
	}
	return wsjson.Write(ctx, conn, WSMessage{
		Type:      ackType,
		SessionID: msg.SessionID,
	})
}

// ConveyWithWS extends the standard Convey flow by first attempting WebSocket
// delivery through the hub before falling back to HTTP direct delivery and
// queueing. This is used by the HTTP /convey endpoint when a hub is available.
func (s *Service) ConveyWithWS(
	sender, receiver attest.PublicKey,
	sessionID string,
	data []byte,
) (bool, error) {
	// Try WebSocket delivery first if hub is available.
	if s.hub != nil && s.hub.Deliver(context.Background(), sender, receiver, sessionID, data) {
		slog.Info("delivered message via websocket hub")
		return true, nil
	}
	// Fall back to standard HTTP delivery + queue.
	return s.Convey(sender, receiver, sessionID, data)
}
