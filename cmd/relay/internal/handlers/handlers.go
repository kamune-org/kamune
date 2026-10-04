package handlers

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/kamune-org/kamune/cmd/relay/internal/config"
	"github.com/kamune-org/kamune/cmd/relay/internal/services"
)

type Handler struct {
	service        *services.Service
	clientIPHeader string
	trustedProxies []*net.IPNet

	// noHeaderOnce reports, once, a trusted proxy's request that had no
	// usable address in clientIPHeader.
	noHeaderOnce sync.Once
}

func New(service *services.Service, cfg config.Config) *Handler {
	trustedProxies := make([]*net.IPNet, 0, len(cfg.Server.TrustedProxies))
	for _, cidr := range cfg.Server.TrustedProxies {
		_, block, _ := net.ParseCIDR(cidr)
		trustedProxies = append(trustedProxies, block)
	}
	header := cfg.Server.ClientIPHeader
	if header == "" {
		header = config.DefaultClientIPHeader
	}
	return &Handler{
		service:        service,
		clientIPHeader: http.CanonicalHeaderKey(header),
		trustedProxies: trustedProxies,
	}
}

// clientIP returns the address r is keyed and logged by. The first time a
// trusted proxy's request has no usable address in the configured header,
// it logs a warning: such a request is keyed by the proxy's address, so
// if the proxy never sets that header, all its clients share one quota.
func (h *Handler) clientIP(r *http.Request) string {
	ip := clientIP(r, h.trustedProxies, h.clientIPHeader)
	if ip != validateIP(r.RemoteAddr) ||
		!ipInRanges(net.ParseIP(ip), h.trustedProxies) {
		return ip
	}
	h.noHeaderOnce.Do(func() {
		slog.Warn(
			"trusted proxy sent a request without a usable client "+
				"address header; requests like it share the proxy's "+
				"rate limit (logged once)",
			slog.String("proxy", ip),
			slog.String("header", h.clientIPHeader),
		)
	})
	return ip
}

func (h *Handler) HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":       "ok",
		"uptime":       time.Since(h.service.StartedAt()).String(),
		"sessionCount": h.service.SessionCount(),
	})
}

func (h *Handler) EchoIPHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ip := h.clientIP(r)
	json.NewEncoder(w).Encode(map[string]string{"ip": ip})
}
