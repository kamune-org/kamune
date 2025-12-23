package handlers

import (
	"net"
	"net/http"
	"strings"

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
	// Prefer explicit real IP header
	ip := r.Header.Get("X-Real-Ip")
	if ip != "" {
		if host, _, err := net.SplitHostPort(strings.TrimSpace(ip)); err == nil {
			return host
		}
		return strings.TrimSpace(ip)
	}

	// X-Forwarded-For may contain a comma-separated list; take the left-most
	ip = ParseForwardedIP(r.Header.Get("X-Forwarded-For"))
	if ip != "" {
		return ip
	}

	// Cloudflare connecting IP
	ip = r.Header.Get("CF-Connecting-IP")
	if ip != "" {
		if host, _, err := net.SplitHostPort(strings.TrimSpace(ip)); err == nil {
			return host
		}
		return strings.TrimSpace(ip)
	}

	// Fallback to RemoteAddr (may include port)
	ip = r.RemoteAddr
	if host, _, err := net.SplitHostPort(strings.TrimSpace(ip)); err == nil {
		return host
	}
	return strings.TrimSpace(ip)
}
