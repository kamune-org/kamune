package services

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/kamune-org/kamune/pkg/attest"
)

// WebhookEvent represents the JSON payload sent to a registered webhook URL
// when a message arrives for a peer.
type WebhookEvent struct {
	Event     string `json:"event"`
	Sender    string `json:"sender"`
	Receiver  string `json:"receiver"`
	SessionID string `json:"session_id"`
	QueueLen  uint64 `json:"queue_len"`
	Timestamp string `json:"timestamp"`
}

// webhookEntry holds a registered webhook URL and its associated public key.
type webhookEntry struct {
	url       string
	publicKey attest.PublicKey
}

// WebhookRegistry manages webhook callback registrations keyed by the
// base64-encoded marshalled public key of each peer.
type WebhookRegistry struct {
	mu      sync.RWMutex
	hooks   map[string]*webhookEntry // base64(pubkey) -> entry
	client  *http.Client
	timeout time.Duration
}

const (
	defaultWebhookTimeout = 5 * time.Second
)

// NewWebhookRegistry creates a new webhook registry with sensible defaults.
func NewWebhookRegistry() *WebhookRegistry {
	return &WebhookRegistry{
		hooks:   make(map[string]*webhookEntry),
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
func (wr *WebhookRegistry) Register(pk attest.PublicKey, url string) {
	key := base64.RawURLEncoding.EncodeToString(pk.Marshal())

	wr.mu.Lock()
	defer wr.mu.Unlock()

	wr.hooks[key] = &webhookEntry{
		url:       url,
		publicKey: pk,
	}

	slog.Info("webhook: registered",
		slog.String("peer", key),
		slog.String("url", url),
	)
}

// Unregister removes a webhook registration for the given public key.
// It returns true if a registration was found and removed.
func (wr *WebhookRegistry) Unregister(pk attest.PublicKey) bool {
	key := base64.RawURLEncoding.EncodeToString(pk.Marshal())

	wr.mu.Lock()
	defer wr.mu.Unlock()

	if _, ok := wr.hooks[key]; ok {
		delete(wr.hooks, key)
		slog.Info("webhook: unregistered", slog.String("peer", key))
		return true
	}
	return false
}

// Lookup returns the webhook URL registered for the given public key, or
// empty string if none is registered.
func (wr *WebhookRegistry) Lookup(pk attest.PublicKey) string {
	key := base64.RawURLEncoding.EncodeToString(pk.Marshal())

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
	receiver attest.PublicKey,
	sender attest.PublicKey,
	sessionID string,
	queueLen uint64,
) {
	receiverKey := base64.RawURLEncoding.EncodeToString(receiver.Marshal())

	wr.mu.RLock()
	entry, ok := wr.hooks[receiverKey]
	wr.mu.RUnlock()

	if !ok {
		return
	}

	senderKey := base64.RawURLEncoding.EncodeToString(sender.Marshal())
	event := WebhookEvent{
		Event:     "message_arrived",
		Sender:    senderKey,
		Receiver:  receiverKey,
		SessionID: sessionID,
		QueueLen:  queueLen,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	body, err := json.Marshal(event)
	if err != nil {
		slog.Error("webhook: failed to marshal event",
			slog.String("peer", receiverKey),
			slog.Any("err", err),
		)
		return
	}

	// Fire asynchronously so we never block the caller.
	go wr.fire(entry.url, receiverKey, body)
}

// fire performs the actual HTTP POST to the webhook URL. It is intended to
// be called in a goroutine.
func (wr *WebhookRegistry) fire(url, peerKey string, body []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), wr.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		slog.Error("webhook: failed to create request",
			slog.String("peer", peerKey),
			slog.String("url", url),
			slog.Any("err", err),
		)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := wr.client.Do(req)
	if err != nil {
		slog.Warn("webhook: delivery failed",
			slog.String("peer", peerKey),
			slog.String("url", url),
			slog.Any("err", err),
		)
		return
	}
	_ = resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		slog.Debug("webhook: delivered",
			slog.String("peer", peerKey),
			slog.Int("status", resp.StatusCode),
		)
	} else {
		slog.Warn("webhook: non-success status",
			slog.String("peer", peerKey),
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
	sender, receiver attest.PublicKey,
	sessionID string,
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
		slog.Debug("webhook: failed to get queue length for notification",
			slog.Any("err", err),
		)
		queueLen = 0
	}

	s.webhooks.Notify(receiver, sender, sessionID, queueLen)
}

// RegisterWebhook registers a webhook URL for the given public key.
func (s *Service) RegisterWebhook(pubKey []byte, url string) error {
	pk, err := s.ParsePublicKeyFor(pubKey)
	if err != nil {
		return fmt.Errorf("parsing public key: %w", err)
	}
	s.webhooks.Register(pk, url)
	return nil
}

// UnregisterWebhook removes a webhook registration for the given public key.
func (s *Service) UnregisterWebhook(pubKey []byte) (bool, error) {
	pk, err := s.ParsePublicKeyFor(pubKey)
	if err != nil {
		return false, fmt.Errorf("parsing public key: %w", err)
	}
	return s.webhooks.Unregister(pk), nil
}
