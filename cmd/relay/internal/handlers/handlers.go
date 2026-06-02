package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/kamune-org/kamune/cmd/relay/internal/config"
	"github.com/kamune-org/kamune/cmd/relay/internal/services"
)

type Handler struct {
	service *services.Service
}

func New(service *services.Service, _ config.Config) *Handler {
	return &Handler{service: service}
}

// WebSocketHandlerNoMiddleware returns the WebSocket handler without middleware
// wrapping, so that http.Hijacker is preserved for the WebSocket upgrade.
func WebSocketHandlerNoMiddleware(service *services.Service) http.HandlerFunc {
	return (&Handler{service: service}).WebSocketHandler
}

func (h *Handler) HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":       "ok",
		"uptime":       h.service.StartedAt().String(),
		"sessionCount": h.service.SessionCount(),
	})
}

func (h *Handler) EchoIPHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"ip": clientIP(r)})
}
