package queuehndlr

import (
	"net/http"

	"github.com/hossein1376/grape"
	"github.com/kamune-org/kamune/relay/internal/services"
)

type QueueHandler struct {
	service *services.Service
}

func New(r *grape.Router, service *services.Service) *QueueHandler {
	h := &QueueHandler{service: service}

	r.Post("", h.NewQueueHandler)

	return h
}

type newQueueRequest struct {
	SessionID string `json:"session_id"`
}

func (h *QueueHandler) NewQueueHandler(w http.ResponseWriter, r *http.Request) {

}
