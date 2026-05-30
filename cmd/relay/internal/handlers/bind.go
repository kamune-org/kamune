package handlers

import (
	"errors"

	"github.com/kamune-org/kamune/cmd/relay/internal/model"
)

var (
	ErrMissingPubKey = errors.New("public key param is required")
)

type registerPeerRequest struct {
	PublicKey model.PublicKey `json:"public_key"`
	Addr      []string        `json:"address"`
}

type conveyRequest struct {
	Sender    model.PublicKey `json:"sender"`
	Receiver  model.PublicKey `json:"receiver"`
	SessionID string          `json:"session_id"`
	Data      string          `json:"data"`
}

func (req conveyRequest) Validate() error {
	if req.SessionID == "" {
		return errors.New("empty session id")
	}
	if req.Data == "" {
		return errors.New("empty data")
	}
	return nil
}

type refreshRequest struct {
	Addr []string `json:"address"`
}

type webhookRequest struct {
	PublicKey model.PublicKey `json:"public_key"`
	URL       string          `json:"url"`
}

func (req webhookRequest) Validate() error {
	if req.URL == "" {
		return errors.New("empty url")
	}
	return nil
}
