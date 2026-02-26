package services

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kamune-org/kamune/pkg/attest"
)

const defaultDeliveryTimeout = 5 * time.Second

// deliveryClient is a package-level HTTP client reused across all Convey calls
// to benefit from connection pooling. The per-request timeout is enforced via
// context deadlines, not the client's Timeout field, so we leave Timeout at 0.
var deliveryClient = &http.Client{
	Transport: &http.Transport{
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
	},
}

// Convey tries to deliver `data` directly to the receiver's registered addresses.
// If any direct delivery attempt succeeds (HTTP 2xx), Convey returns (true, nil).
// If all attempts fail (or no addresses are available), the message is enqueued
// via PushQueue and Convey returns (false, nil) on successful enqueue or (false, err)
// if enqueueing itself fails.
func (s *Service) Convey(sender, receiver attest.PublicKey, sessionID string, data []byte) (bool, error) {
	// Try to obtain peer addresses. Non-fatal: if inquiry fails we fall back to queueing.
	var addresses []string
	if peer, err := s.InquiryPeer(receiver.Marshal()); err == nil && peer != nil {
		addresses = peer.Address
	} else if err != nil {
		slog.Debug("inquiry peer failed (will fallback to queue)", slog.Any("err", err))
	}

	// Attempt direct delivery if we have addresses.
	if len(addresses) > 0 {
		timeout := s.deliveryTimeout()
		for _, addr := range addresses {
			targetURL, err := buildDeliveryURL(addr)
			if err != nil {
				slog.Debug("skipping address - invalid URL", slog.String("addr", addr), slog.Any("err", err))
				continue
			}

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL.String(), bytes.NewReader(data))
			if err != nil {
				cancel()
				slog.Debug("failed to create request", slog.String("url", targetURL.String()), slog.Any("err", err))
				continue
			}
			req.Header.Set("Content-Type", "application/octet-stream")

			resp, err := deliveryClient.Do(req)
			cancel()
			if err != nil {
				slog.Debug("delivery attempt failed", slog.String("url", targetURL.String()), slog.Any("err", err))
				continue
			}
			_ = resp.Body.Close()

			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				slog.Info("delivered message to peer", slog.String("url", targetURL.String()), slog.Int("status", resp.StatusCode))
				return true, nil
			}

			slog.Debug("delivery returned non-success status", slog.String("url", targetURL.String()), slog.Int("status", resp.StatusCode))
		}
	}

	// Direct delivery didn't succeed; push to queue.
	if err := s.PushQueue(sender, receiver, sessionID, data); err != nil {
		return false, fmt.Errorf("enqueue after failed delivery: %w", err)
	}
	slog.Info("message enqueued after failed delivery attempts")
	return false, nil
}

// deliveryTimeout returns the configured delivery timeout or the default.
func (s *Service) deliveryTimeout() time.Duration {
	if t := s.cfg.Server.DeliveryTimeout; t > 0 {
		return t
	}
	return defaultDeliveryTimeout
}

// buildDeliveryURL builds the final delivery URL for a registered address.
//
// Rules:
//   - If `addr` starts with "http://" or "https://", it is treated as base and
//     "/inbound" is appended if no path exists.
//   - Otherwise, "http://"+addr is used as base and "/inbound" appended.
//
// Examples:
//
//	"1.2.3.4:8080" => http://1.2.3.4:8080/inbound
//	"https://example.com/api" => https://example.com/api/inbound
func buildDeliveryURL(addr string) (*url.URL, error) {
	trimmed := strings.TrimSpace(addr)
	if trimmed == "" {
		return nil, fmt.Errorf("empty address")
	}

	if !strings.HasPrefix(trimmed, "http://") && !strings.HasPrefix(trimmed, "https://") {
		trimmed = "http://" + trimmed
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("parse address: %w", err)
	}

	if u.Path == "" || u.Path == "/" {
		u.Path = "/inbound"
	} else {
		u.Path = strings.TrimRight(u.Path, "/") + "/inbound"
	}

	return u, nil
}
