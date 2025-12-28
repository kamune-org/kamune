package queuehndlr

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/hossein1376/grape"
	"github.com/hossein1376/grape/errs"

	"github.com/kamune-org/kamune/pkg/attest"
	handlers "github.com/kamune-org/kamune/relay/internal/handlers"
	"github.com/kamune-org/kamune/relay/internal/services"
)

type QueueHandler struct {
	service *services.Service
}

func New(r *grape.Router, service *services.Service) *QueueHandler {
	h := &QueueHandler{service: service}

	// POST /queues -> push a message to a queue
	r.Post("", h.NewQueueHandler)
	// GET  /queues -> pop a message from a queue (uses query params)
	r.Get("", h.PopQueueHandler)

	return h
}

// pushQueueRequest is the expected JSON body for pushing a message.
// - sender: base64 raw public key of the sender
// - receiver: base64 raw public key of the receiver
// - session_id: application-level session identifier
// - data: base64-encoded payload to enqueue
type pushQueueRequest struct {
	Sender    string `json:"sender"`
	Receiver  string `json:"receiver"`
	SessionID string `json:"session_id"`
	Data      string `json:"data"`
}

// Use centralized parsing helpers from the parent handlers package.
// Decoding/parsing utilities live in relay/internal/handlers/parse.go
// and are imported as the `handlers` package above.

// NewQueueHandler handles pushing a message to the queue.
func (h *QueueHandler) NewQueueHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	req, err := grape.ReadJSON[pushQueueRequest](w, r)
	if err != nil {
		grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErr(err)))
		return
	}

	// parse sender and receiver via centralized helper
	senderPK, receiverPK, err := handlers.DecodeAndParsePair(req.Sender, req.Receiver, h.service)
	if err != nil {
		grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErr(fmt.Errorf("parsing keys: %w", err))))
		return
	}

	// decode payload using centralized helper
	payload, err := handlers.DecodePayloadFromBase64(req.Data)
	if err != nil {
		grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErr(fmt.Errorf("data: %w", err))))
		return
	}

	// push to queue
	err = h.service.PushQueue(senderPK, receiverPK, req.SessionID, payload)
	if err != nil {
		// map sentinel service errors to HTTP statuses
		switch {
		case errors.Is(err, services.ErrMessageTooLarge):
			// 413 Payload Too Large
			grape.Respond(ctx, w, http.StatusRequestEntityTooLarge, grape.Map{"error": "message too large"})
			return
		case errors.Is(err, services.ErrQueueFull):
			// 409 Conflict per your preference for queue-full condition
			grape.Respond(ctx, w, http.StatusConflict, grape.Map{"error": "queue full"})
			return
		default:
			// Fallback to generic error extraction/translation
			grape.ExtractFromErr(ctx, w, fmt.Errorf("push queue: %w", err))
			return
		}
	}

	grape.Respond(ctx, w, http.StatusCreated, grape.Map{"status": "ok"})
}

// PopQueueHandler pops a message from the queue.
// Expects query parameters:
// - sender: base64 raw public key of the sender
// - receiver: base64 raw public key of the receiver
// - session: session id
func (h *QueueHandler) PopQueueHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	senderEnc := q.Get("sender")
	receiverEnc := q.Get("receiver")
	sessionID := q.Get("session")

	if senderEnc == "" || receiverEnc == "" || sessionID == "" {
		grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErr(errors.New("sender, receiver and session query params are required"))))
		return
	}

	// parse sender and receiver via centralized helper
	senderPK, receiverPK, err := handlers.DecodeAndParsePair(senderEnc, receiverEnc, h.service)
	if err != nil {
		grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErr(fmt.Errorf("parsing keys: %w", err))))
		return
	}

	data, err := h.service.PopQueue(senderPK, receiverPK, sessionID)
	if err != nil {
		grape.ExtractFromErr(ctx, w, fmt.Errorf("pop queue: %w", err))
		return
	}

	// If queue is empty, return No Content
	if data == nil {
		grape.Respond(ctx, w, http.StatusNoContent, nil)
		return
	}

	// return base64 encoded payload
	enc := handlers.EncodePayloadToBase64(data)
	grape.Respond(ctx, w, http.StatusOK, grape.Map{"data": enc})
}

// ParsePublicKeyFor is a small helper to convert raw key bytes into attest.PublicKey
// using the service's configured identity algorithm. It delegates to the service
// helper to keep parsing logic centralized.
func (s *QueueHandler) ParsePublicKeyFor(key []byte) (attest.PublicKey, error) {
	return s.service.ParsePublicKeyFor(key)
}
