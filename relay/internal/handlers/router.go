package handlers

import (
	"net/http"

	"github.com/hossein1376/grape"

	"github.com/kamune-org/kamune/relay/internal/config"
)

func newRouter(h *Handler, cfg config.Config) *grape.Router {
	r := grape.NewRouter()
	r.UseAll(
		grape.RequestIDMiddleware,
		grape.LoggerMiddleware,
		grape.RecoverMiddleware,
		grape.CORSMiddleware,
	)
	if cfg.RateLimit.Enabled {
		r.UseAll(rateLimitMiddleware(h.service))
	}

	r.Get("/identity", h.IdentityHandler)
	r.Get("/ip", h.EchoIPHandler)

	peers := r.Group("/peers")
	peers.Post("", h.RegisterPeerHandler)
	peers.Get("", h.InquiryPeerHandler)
	peers.Delete("/{id}", h.DiscardPeerHandler)

	return r
}

func clientIP(r *http.Request) string {
	ip := r.Header.Get("X-Real-Ip")
	if ip == "" {
		ip = r.Header.Get("X-Forwarded-For")
	}
	if ip == "" {
		ip = r.Header.Get("CF-Connecting-IP")
	}
	if ip == "" {
		ip = r.RemoteAddr
	}
	return ip
}
