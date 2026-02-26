package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/hossein1376/grape"
	"github.com/hossein1376/grape/errs"

	"github.com/kamune-org/kamune/relay/internal/config"
	"github.com/kamune-org/kamune/relay/internal/handlers/serde"
	"github.com/kamune-org/kamune/relay/internal/model"
	"github.com/kamune-org/kamune/relay/internal/services"
)

type Handler struct {
	service *services.Service
}

func New(service *services.Service, cfg config.Config) *grape.Router {
	h := &Handler{service: service}
	return newRouter(h, cfg)
}

func (h *Handler) HealthHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	status, err := h.service.Health()
	if err != nil {
		grape.Respond(ctx, w, http.StatusServiceUnavailable, grape.Map{"health": status})
		return
	}
	grape.Respond(ctx, w, http.StatusOK, grape.Map{"health": status})
}

func (h *Handler) IdentityHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	format := r.URL.Query().Get("format")
	identity := h.service.Identity(format)
	grape.Respond(ctx, w, http.StatusOK, grape.Map{"identity": identity})
}

func (h *Handler) EchoIPHandler(w http.ResponseWriter, r *http.Request) {
	grape.Respond(r.Context(), w, http.StatusOK, grape.Map{"ip": clientIP(r)})
}

func (h *Handler) ConveyHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	type conveyRequest struct {
		Sender    string `json:"sender"`
		Receiver  string `json:"receiver"`
		SessionID string `json:"session_id"`
		Data      string `json:"data"`
	}

	req, err := grape.ReadJSON[conveyRequest](w, r)
	if err != nil {
		grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErr(err)))
		return
	}

	if req.Sender == "" || req.Receiver == "" || req.SessionID == "" || req.Data == "" {
		grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErr(fmt.Errorf("sender, receiver, session_id and data are required"))))
		return
	}

	// Decode and parse keys & payload using centralized helpers
	senderPK, err := serde.ParsePublicKeyFromBase64(req.Sender, h.service)
	if err != nil {
		grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErr(fmt.Errorf("sender: %w", err))))
		return
	}
	receiverPK, err := serde.ParsePublicKeyFromBase64(req.Receiver, h.service)
	if err != nil {
		grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErr(fmt.Errorf("receiver: %w", err))))
		return
	}
	dataRaw, err := serde.DecodePayloadFromBase64(req.Data)
	if err != nil {
		grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErr(fmt.Errorf("data: %w", err))))
		return
	}

	// Attempt convey with WebSocket delivery first, then HTTP, then queue.
	delivered, err := h.service.ConveyWithWS(senderPK, receiverPK, req.SessionID, dataRaw)
	if err != nil {
		grape.ExtractFromErr(ctx, w, err)
		return
	}

	if m := h.service.Metrics(); m != nil {
		m.RecordConveyResult(delivered)
	}

	if delivered {
		grape.Respond(ctx, w, http.StatusOK, grape.Map{"delivered": true})
		return
	}
	// Not delivered directly; message was queued
	grape.Respond(ctx, w, http.StatusAccepted, grape.Map{"queued": true})
}

func (h *Handler) RegisterPeerHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	req, err := registerPeerBinder(w, r)
	if err != nil {
		grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErr(err)))
		return
	}
	addr := make([]string, len(req.Addr)+1)
	copy(addr, req.Addr)
	addr[len(req.Addr)] = clientIP(r)

	peer, err := h.service.RegisterPeer(req.publicKey, req.Identity, addr)
	if err != nil {
		if errors.Is(err, services.ErrExistingPeer) {
			peer.ID = model.NewPeerID()
			grape.Respond(ctx, w, http.StatusConflict, grape.Map{"peer": peer})
			return
		}
		grape.ExtractFromErr(ctx, w, err)
		return
	}

	if m := h.service.Metrics(); m != nil {
		m.IncPeersRegistered()
	}

	grape.Respond(ctx, w, http.StatusCreated, grape.Map{"peer": peer})
}

// RefreshPeerHandler renews the TTL of an existing peer registration.
// The caller provides their public key (as base64 query param `key`) and
// optionally a JSON body with updated addresses.
func (h *Handler) RefreshPeerHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	key, err := readKeyFromQuery(r.URL.Query())
	if err != nil {
		grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErr(err)))
		return
	}

	// Optionally read new addresses from the body.
	type refreshRequest struct {
		Addr []string `json:"address"`
	}
	var newAddr []string
	if r.ContentLength > 0 {
		req, err := grape.ReadJSON[refreshRequest](w, r)
		if err != nil {
			grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErr(err)))
			return
		}
		if req != nil {
			newAddr = req.Addr
		}
	}

	peer, err := h.service.RefreshPeer(key, newAddr)
	if err != nil {
		grape.ExtractFromErr(ctx, w, err)
		return
	}

	if m := h.service.Metrics(); m != nil {
		m.IncPeersRefreshed()
	}

	grape.Respond(ctx, w, http.StatusOK, grape.Map{"peer": peer})
}

// BatchPopQueueHandler pops multiple messages from the queue in one request.
// Expects the same query parameters as PopQueueHandler plus an optional
// `limit` parameter (default 10, max 100).
func (h *Handler) BatchPopQueueHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	senderEnc := q.Get("sender")
	receiverEnc := q.Get("receiver")
	sessionID := q.Get("session")

	if senderEnc == "" || receiverEnc == "" || sessionID == "" {
		grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErr(
			fmt.Errorf("sender, receiver and session query params are required"),
		)))
		return
	}

	senderPK, receiverPK, err := serde.DecodeAndParsePair(senderEnc, receiverEnc, h.service)
	if err != nil {
		grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErr(
			fmt.Errorf("parsing keys: %w", err),
		)))
		return
	}

	limit := services.DefaultBatchSize
	if ls := q.Get("limit"); ls != "" {
		parsed, err := strconv.Atoi(ls)
		if err != nil || parsed < 1 {
			grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErr(
				fmt.Errorf("invalid limit: %q", ls),
			)))
			return
		}
		limit = parsed
	}

	messages, err := h.service.BatchPopQueue(senderPK, receiverPK, sessionID, limit)
	if err != nil {
		grape.ExtractFromErr(ctx, w, fmt.Errorf("batch pop queue: %w", err))
		return
	}

	if len(messages) == 0 {
		grape.Respond(ctx, w, http.StatusNoContent, nil)
		return
	}

	if m := h.service.Metrics(); m != nil {
		m.IncBatchDrains()
		m.AddBatchDrainItems(int64(len(messages)))
		for range messages {
			m.IncMessagesPopped()
		}
	}

	// Encode each message as base64.
	encoded := make([]string, len(messages))
	for i, msg := range messages {
		encoded[i] = serde.EncodePayloadToBase64(msg)
	}

	grape.Respond(ctx, w, http.StatusOK, grape.Map{
		"data":  encoded,
		"count": len(encoded),
	})
}

// RegisterWebhookHandler registers a webhook callback URL for a peer.
// When a message arrives for that peer and is enqueued, the relay will POST
// a JSON notification to the provided URL.
func (h *Handler) RegisterWebhookHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	type webhookRequest struct {
		PublicKey string `json:"public_key"`
		URL       string `json:"url"`
	}

	req, err := grape.ReadJSON[webhookRequest](w, r)
	if err != nil {
		grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErr(err)))
		return
	}

	if req.PublicKey == "" || req.URL == "" {
		grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErr(
			fmt.Errorf("public_key and url are required"),
		)))
		return
	}

	pubKeyRaw, err := serde.DecodeBase64Raw(req.PublicKey)
	if err != nil {
		grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErr(
			fmt.Errorf("decoding public_key: %w", err),
		)))
		return
	}

	if err := h.service.RegisterWebhook(pubKeyRaw, req.URL); err != nil {
		grape.ExtractFromErr(ctx, w, fmt.Errorf("register webhook: %w", err))
		return
	}

	grape.Respond(ctx, w, http.StatusCreated, grape.Map{"status": "ok"})
}

// UnregisterWebhookHandler removes a webhook registration for a peer.
func (h *Handler) UnregisterWebhookHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	key, err := readKeyFromQuery(r.URL.Query())
	if err != nil {
		grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErr(err)))
		return
	}

	removed, err := h.service.UnregisterWebhook(key)
	if err != nil {
		grape.ExtractFromErr(ctx, w, fmt.Errorf("unregister webhook: %w", err))
		return
	}

	if !removed {
		grape.ExtractFromErr(ctx, w, errs.NotFound(errs.WithErr(
			fmt.Errorf("no webhook registered for this key"),
		)))
		return
	}

	grape.Respond(ctx, w, http.StatusNoContent, nil)
}

func (h *Handler) InquiryPeerHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	key, err := readKeyFromQuery(r.URL.Query())
	if err != nil {
		grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErr(err)))
		return
	}
	peer, err := h.service.InquiryPeer(key)
	if err != nil {
		grape.ExtractFromErr(ctx, w, err)
		return
	}
	peer.ID = model.EmptyPeerID() // remove peer id from response

	grape.Respond(ctx, w, http.StatusOK, grape.Map{"peer": peer})
}

func (h *Handler) DiscardPeerHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	key, err := readKeyFromQuery(r.URL.Query())
	if err != nil {
		grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErr(err)))
		return
	}
	err = h.service.DeletePeer(key)
	if err != nil {
		grape.ExtractFromErr(ctx, w, err)
		return
	}

	grape.Respond(ctx, w, http.StatusNoContent, nil)
}

// MetricsHandler serves the Prometheus-compatible metrics endpoint.
func (h *Handler) MetricsHandler(w http.ResponseWriter, r *http.Request) {
	if m := h.service.Metrics(); m != nil {
		m.ServeHTTP(w, r)
		return
	}
	grape.Respond(r.Context(), w, http.StatusNotFound, grape.Map{"error": "metrics not available"})
}
