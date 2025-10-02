package services

import (
	"errors"
	"net/http"

	"github.com/hossein1376/grape/errs"

	"github.com/kamune-org/kamune/relay/internal/model"
)

var (
	ErrMessageTooLarge = errors.New("message is too large")
	ErrQueueFull       = errors.New("session queue is full")

	queueNS      = model.NewNameSpace("queue")
	queueCountNS = model.NewNameSpace("qu_count")
)

func (s *Service) QueueMessage(
	senderID, receiverID model.PeerID, msg []byte,
) error {
	if len(msg) > s.cfg.Storage.MaxMessageSize {
		return errs.New(ErrMessageTooLarge, http.StatusRequestEntityTooLarge)
	}
	return nil
}
