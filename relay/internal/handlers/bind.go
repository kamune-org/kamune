package handlers

import (
	"errors"

	"github.com/kamune-org/kamune/pkg/attest"
)

var (
	ErrMissingPubKey = errors.New("public key param is required")
)

type registerPeerRequest struct {
	Identity attest.Identity `json:"identity"`
	Addr     []string        `json:"address"`
}

type conveyRequest struct {
	Sender    attest.Identity `json:"sender"`
	Receiver  attest.Identity `json:"receiver"`
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
	Peer attest.Identity `json:"peer"`
	URL  string          `json:"url"`
}

func (req webhookRequest) Validate() error {
	if req.URL == "" {
		return errors.New("empty url")
	}
	return nil
}
