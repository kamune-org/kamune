package services

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/hossein1376/grape/slogger"

	"github.com/kamune-org/kamune/relay/internal/model"
)

// WebhookEvent represents the JSON payload sent to a registered webhook URL
// when a message arrives for a peer.
type WebhookEvent struct {
	Event     string          `json:"event"`
	Sender    model.PublicKey `json:"sender"`
	Receiver  model.PublicKey `json:"receiver"`
	SessionID string          `json:"session_id"`
	QueueLen  uint64          `json:"queue_len"`
	Timestamp string          `json:"timestamp"`
}

// webhookEntry holds a registered webhook URL and its associated public key.
type webhookEntry struct {
	url string
}

// WebhookRegistry manages webhook callback registrations keyed by the
// base64-encoded marshaled public key of each peer.
type WebhookRegistry struct {
	mu      sync.RWMutex
	hooks   map[model.PublicKey]*webhookEntry // base64(pubkey) -> entry
	client  *http.Client
	timeout time.Duration
}

const (
	defaultWebhookTimeout = 5 * time.Second
)

// NewWebhookRegistry creates a new webhook registry with sensible defaults.
func NewWebhookRegistry() *WebhookRegistry {
	return &WebhookRegistry{
		hooks:   make(map[model.PublicKey]*webhookEntry),
		timeout: defaultWebhookTimeout,
		client: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:        32,
				MaxIdleConnsPerHost: 4,
				IdleConnTimeout:     60 * time.Second,
			},
		},
	}
}

// Register adds or replaces a webhook URL for the given public key.
func (wr *WebhookRegistry) Register(key model.PublicKey, url string) {
	wr.mu.Lock()
	defer wr.mu.Unlock()

	wr.hooks[key] = &webhookEntry{
		url: url,
	}

	slog.Info(
		"webhook: registered",
		slogger.String("peer", key),
		slog.String("url", url),
	)
}

// Unregister removes a webhook registration for the given public key.
// It returns true if a registration was found and removed.
func (wr *WebhookRegistry) Unregister(key model.PublicKey) bool {
	wr.mu.Lock()
	defer wr.mu.Unlock()

	if _, ok := wr.hooks[key]; ok {
		delete(wr.hooks, key)
		slog.Info("webhook: unregistered", slogger.String("peer", key))
		return true
	}
	return false
}

// Lookup returns the webhook URL registered for the given public key, or
// empty string if none is registered.
func (wr *WebhookRegistry) Lookup(key model.PublicKey) string {
	wr.mu.RLock()
	defer wr.mu.RUnlock()

	if entry, ok := wr.hooks[key]; ok {
		return entry.url
	}
	return ""
}

// Notify sends a webhook notification for a message arrival event.
// It is safe to call concurrently; the HTTP request is made with a bounded
// timeout. Delivery failures are logged but not returned — webhook delivery
// is best-effort.
func (wr *WebhookRegistry) Notify(
	receiver, sender model.PublicKey, sessionID string, queueLen uint64,
) {
	wr.mu.RLock()
	entry, ok := wr.hooks[receiver]
	wr.mu.RUnlock()

	if !ok {
		return
	}

	event := WebhookEvent{
		Event:     "message_arrived",
		Sender:    sender,
		Receiver:  receiver,
		SessionID: sessionID,
		QueueLen:  queueLen,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	body, err := json.Marshal(event)
	if err != nil {
		slog.Error(
			"webhook: failed to marshal event",
			slogger.String("peer", receiver),
			slogger.Err("error", err),
		)
		return
	}

	// Fire asynchronously so we never block the caller.
	go wr.fire(entry.url, receiver, body)
}

// fire performs the actual HTTP POST to the webhook URL. It is intended to
// be called in a goroutine.
func (wr *WebhookRegistry) fire(
	url string, peer model.PublicKey, body []byte,
) {
	ctx, cancel := context.WithTimeout(context.Background(), wr.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, url, bytes.NewReader(body),
	)
	if err != nil {
		slog.Error(
			"webhook: failed to create request",
			slogger.String("peer", peer),
			slog.String("url", url),
			slogger.Err("error", err),
		)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := wr.client.Do(req)
	if err != nil {
		slog.Warn(
			"webhook: delivery failed",
			slogger.String("peer", peer),
			slog.String("url", url),
			slogger.Err("error", err),
		)
		return
	}
	_ = resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		slog.Debug(
			"webhook: delivered",
			slogger.String("peer", peer),
			slog.Int("status", resp.StatusCode),
		)
	} else {
		slog.Warn(
			"webhook: non-success status",
			slogger.String("peer", peer),
			slog.String("url", url),
			slog.Int("status", resp.StatusCode),
		)
	}
}

// Webhooks returns the service's webhook registry.
func (s *Service) Webhooks() *WebhookRegistry {
	return s.webhooks
}

// NotifyWebhook fires a webhook notification for the receiver if one is
// registered. It fetches the current queue length for context and delegates
// to the webhook registry. Safe to call even if no webhook is registered.
func (s *Service) NotifyWebhook(
	sender, receiver model.PublicKey, sessionID string,
) {
	if s.webhooks == nil {
		return
	}

	url := s.webhooks.Lookup(receiver)
	if url == "" {
		return
	}

	// Best-effort queue length lookup for the notification payload.
	queueLen, err := s.QueueLen(sender, receiver, sessionID)
	if err != nil {
		slog.Debug(
			"webhook: failed to get queue length for notification",
			slogger.Err("error", err),
		)
		queueLen = 0
	}

	s.webhooks.Notify(receiver, sender, sessionID, queueLen)
}

// RegisterWebhook registers a webhook URL for the given public key.
func (s *Service) RegisterWebhook(pub model.PublicKey, url string) {
	s.webhooks.Register(pub, url)
}

// UnregisterWebhook removes a webhook registration for the given public key.
func (s *Service) UnregisterWebhook(pub model.PublicKey) bool {
	return s.webhooks.Unregister(pub)
}
