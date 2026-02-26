package handlers

import (
	"net"
	"net/http"
	"strings"

	"github.com/hossein1376/grape"

	"github.com/kamune-org/kamune/relay/internal/config"
	queuehndlr "github.com/kamune-org/kamune/relay/internal/handlers/queuehndlr"
	"github.com/kamune-org/kamune/relay/internal/services"
)

func newRouter(h *Handler, cfg config.Config) *grape.Router {
	r := grape.NewRouter()
	r.UseAll(
		grape.RequestIDMiddleware,
		grape.LoggerMiddleware,
		grape.RecoverMiddleware,
		grape.CORSMiddleware,
	)

	// Metrics middleware — records request count, errors and latency.
	if m := h.service.Metrics(); m != nil {
		r.UseAll(services.MetricsMiddleware(m))
	}

	if cfg.RateLimit.Enabled {
		r.UseAll(rateLimitMiddleware(h.service))
	}

	r.Get("/health", h.HealthHandler)
	r.Get("/identity", h.IdentityHandler)
	r.Get("/ip", h.EchoIPHandler)

	// Metrics endpoint (Prometheus-compatible text exposition format).
	r.Get("/metrics", h.MetricsHandler)

	peers := r.Group("/peers")
	peers.Post("", h.RegisterPeerHandler)
	peers.Get("", h.InquiryPeerHandler)
	peers.Delete("/{id}", h.DiscardPeerHandler)
	// Peer refresh / heartbeat — renew TTL without re-registering.
	peers.Post("/refresh", h.RefreshPeerHandler)

	r.Post("/convey", h.ConveyHandler)

	// Queue endpoints (push/pop) - registered under /queues
	queues := r.Group("/queues")
	queuehndlr.New(queues, h.service)
	// Batch queue drain — pop multiple messages in one request.
	queues.Get("/batch", h.BatchPopQueueHandler)

	// WebSocket endpoint for persistent bidirectional relay connections.
	r.Get("/ws", h.WebSocketHandler)

	// Webhook callback registrations.
	webhooks := r.Group("/webhooks")
	webhooks.Post("", h.RegisterWebhookHandler)
	webhooks.Delete("", h.UnregisterWebhookHandler)

	return r
}

// privateRanges contains the CIDR blocks for addresses that are considered
// non-routable (RFC 1918, RFC 4193, loopback, link-local, etc.).
// These are used to skip untrusted entries in multi-hop proxy headers.
var privateRanges []*net.IPNet

func init() {
	cidrs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	for _, cidr := range cidrs {
		_, block, _ := net.ParseCIDR(cidr)
		if block != nil {
			privateRanges = append(privateRanges, block)
		}
	}
}

// isPrivateIP reports whether ip falls inside a well-known non-routable range.
func isPrivateIP(ip net.IP) bool {
	for _, block := range privateRanges {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// extractIP strips an optional port from s, trims whitespace, and returns the
// bare IP string. If s is already a bare IP (no port) it is returned as-is.
func extractIP(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// Try to split host:port. SplitHostPort fails when there is no port,
	// which is the common case for most proxy headers.
	if host, _, err := net.SplitHostPort(s); err == nil {
		return host
	}
	return s
}

// validateIP extracts a bare IP from s, parses it, and returns the string
// representation only when it is a valid IP address. Returns "" otherwise.
func validateIP(s string) string {
	raw := extractIP(s)
	if raw == "" {
		return ""
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		return ""
	}
	return ip.String()
}

// singleHeader reads a single-value proxy header, validates it, and returns
// the IP or "".
func singleHeader(r *http.Request, name string) string {
	return validateIP(r.Header.Get(name))
}

// clientIP determines the most likely public IP of the connecting client by
// inspecting well-known proxy headers in priority order, then falling back to
// http.Request.RemoteAddr.
//
// Header priority (first non-empty, valid, public IP wins):
//  1. X-Real-Ip               — set by Nginx and many reverse proxies
//  2. True-Client-IP          — Akamai / some CDNs
//  3. CF-Connecting-IP        — Cloudflare
//  4. Fly-Client-IP           — Fly.io
//  5. Fastly-Client-IP        — Fastly
//  6. X-Forwarded-For         — de-facto standard; may be a comma-separated
//     list — we walk it left-to-right and pick the first
//     valid *public* IP (skipping private / loopback
//     entries that intermediate proxies may have prepended).
//  7. RemoteAddr               — direct connection (last resort)
func clientIP(r *http.Request) string {
	// ── single-value headers (most trustworthy when set by the edge) ─────
	for _, header := range []string{
		"X-Real-Ip",
		"True-Client-IP",
		"CF-Connecting-IP",
		"Fly-Client-IP",
		"Fastly-Client-IP",
	} {
		if ip := singleHeader(r, header); ip != "" {
			return ip
		}
	}

	// ── X-Forwarded-For (multi-value) ────────────────────────────────────
	if ip := ParseForwardedIP(r.Header.Get("X-Forwarded-For")); ip != "" {
		return ip
	}

	// ── Fallback to RemoteAddr ───────────────────────────────────────────
	ip := validateIP(r.RemoteAddr)
	if ip != "" {
		return ip
	}
	// Last-ditch: return RemoteAddr as-is even if we couldn't parse it.
	return extractIP(r.RemoteAddr)
}

// ParseForwardedIP extracts the first valid, public IP from an
// X-Forwarded-For header value. The header is a comma-separated list
// where the left-most entry is typically the original client. Intermediate
// hops may prepend private addresses, so we skip any non-routable IPs and
// return the first public one. If every entry is private (or the header is
// empty), we return the left-most valid IP as a fallback, since in a
// fully-private network that is still the best information we have.
// Returns "" only when the header is empty or contains no parseable IPs.
func ParseForwardedIP(header string) string {
	if header == "" {
		return ""
	}

	var firstValid string
	for _, part := range strings.Split(header, ",") {
		ip := validateIP(part)
		if ip == "" {
			continue
		}
		if firstValid == "" {
			firstValid = ip
		}
		parsed := net.ParseIP(ip)
		if parsed != nil && !isPrivateIP(parsed) {
			return ip
		}
	}
	// All entries were private/loopback; return the left-most valid one.
	return firstValid
}
