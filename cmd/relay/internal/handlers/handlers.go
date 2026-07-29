package handlers

import (
	"encoding/json"
	"net"
	"net/http"

	"github.com/kamune-org/kamune/cmd/relay/internal/config"
	"github.com/kamune-org/kamune/cmd/relay/internal/services"
)

type Handler struct {
	service        *services.Service
	trustedProxies []*net.IPNet
}

func New(service *services.Service, cfg config.Config) *Handler {
	trustedProxies := make([]*net.IPNet, 0, len(cfg.Server.TrustedProxies))
	for _, cidr := range cfg.Server.TrustedProxies {
		_, block, _ := net.ParseCIDR(cidr)
		trustedProxies = append(trustedProxies, block)
	}
	return &Handler{service: service, trustedProxies: trustedProxies}
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
	ip := clientIP(r, h.trustedProxies)
	json.NewEncoder(w).Encode(map[string]string{"ip": ip})
}
