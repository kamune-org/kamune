package services

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"

	"github.com/hossein1376/grape/slogger"

	"github.com/kamune-org/kamune/cmd/relay/internal/model"
	"github.com/kamune-org/kamune/pkg/relayconn/pb"
)

func (s *Service) Hub() *Hub {
	return s.hub
}

func (s *Service) HandleWSRelay(
	ctx context.Context,
	sender model.PublicKey,
	msg *pb.Message,
) error {
	receiver := msg.GetReceiver()
	sessionID := msg.GetSessionId()
	data := msg.GetData()

	if len(receiver) == 0 || sessionID == "" || len(data) == 0 {
		return fmt.Errorf("receiver, session_id and data are required")
	}

	receiverKey := model.PublicKey(base64.RawURLEncoding.EncodeToString(receiver))

	if s.hub != nil && s.hub.Deliver(ctx, sender, receiverKey, sessionID, data) {
		slog.Debug(
			"ws: delivered via hub", slogger.String("receiver", receiverKey),
		)
		return nil
	}

	delivered, err := s.Convey(sender, receiverKey, sessionID, data)
	if err != nil {
		return fmt.Errorf("convey: %w", err)
	}
	_ = delivered

	return nil
}

func (s *Service) ConveyWithWS(
	ctx context.Context,
	sender, receiver model.PublicKey,
	sessionID string,
	data []byte,
) (bool, error) {
	if s.hub != nil && s.hub.Deliver(ctx, sender, receiver, sessionID, data) {
		slog.Info("delivered message via websocket hub")
		return true, nil
	}
	return s.Convey(sender, receiver, sessionID, data)
}
