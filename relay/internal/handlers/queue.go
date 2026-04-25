package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/hossein1376/grape"
	"github.com/hossein1376/grape/errs"

	"github.com/kamune-org/kamune/relay/internal/model"
	"github.com/kamune-org/kamune/relay/internal/services"
)

type pushQueueRequest struct {
	Sender    model.PublicKey `json:"sender"`
	Receiver  model.PublicKey `json:"receiver"`
	SessionID string          `json:"session_id"`
	Data      string          `json:"data"`
}

// NewQueueHandler handles pushing a message to the queue.
func (h *Handler) NewQueueHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	req, err := grape.ReadJSON[pushQueueRequest](w, r)
	if err != nil {
		grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErr(err)))
		return
	}

	// decode payload using centralized helper
	payload, err := decodeBase64Raw(req.Data)
	if err != nil {
		err := fmt.Errorf("data: %w", err)
		grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErrMsg(err)))
		return
	}

	// push to queue
	err = h.service.PushQueue(req.Sender, req.Receiver, req.SessionID, payload)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrMessageTooLarge):
			resp := grape.Map{"error": "message too large"}
			grape.Respond(ctx, w, http.StatusRequestEntityTooLarge, resp)
			return
		case errors.Is(err, services.ErrQueueFull):
			resp := grape.Map{"error": "queue full"}
			grape.Respond(ctx, w, http.StatusConflict, resp)
			return
		default:
			grape.ExtractFromErr(ctx, w, fmt.Errorf("push queue: %w", err))
			return
		}
	}

	if m := h.service.Metrics(); m != nil {
		m.IncMessagesQueued()
	}

	grape.Respond(ctx, w, http.StatusCreated, grape.Map{"status": "ok"})
}

// PopQueueHandler pops a message from the queue.
func (h *Handler) PopQueueHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	sender, err := grape.Query(q, "sender", model.ParsePublicKey)
	if err != nil {
		err = fmt.Errorf("parse sender: %w", err)
		grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErrMsg(err)))
		return
	}
	receiver, err := grape.Query(q, "receiver", model.ParsePublicKey)
	if err != nil {
		err = fmt.Errorf("parse receiver: %w", err)
		grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErrMsg(err)))
		return
	}
	sessionID := q.Get("session")

	data, err := h.service.PopQueue(sender, receiver, sessionID)
	if err != nil {
		grape.ExtractFromErr(ctx, w, fmt.Errorf("pop queue: %w", err))
		return
	}

	// If queue is empty, return No Content
	if data == nil {
		grape.Respond(ctx, w, http.StatusNoContent, nil)
		return
	}

	if m := h.service.Metrics(); m != nil {
		m.IncMessagesPopped()
	}

	// return base64 encoded payload
	enc := encodePayloadToBase64(data)
	grape.Respond(ctx, w, http.StatusOK, grape.Map{"data": enc})
}

// QueueLenHandler returns the number of pending messages in a queue without
// consuming any of them.
// Expects query parameters:
// - sender: base64 raw public key of the sender
// - receiver: base64 raw public key of the receiver
// - session: session id
func (h *Handler) QueueLenHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	sender, err := grape.Query(q, "sender", model.ParsePublicKey)
	if err != nil {
		err = fmt.Errorf("parse sender: %w", err)
		grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErrMsg(err)))
		return
	}
	receiver, err := grape.Query(q, "receiver", model.ParsePublicKey)
	if err != nil {
		err = fmt.Errorf("parse receiver: %w", err)
		grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErrMsg(err)))
		return
	}
	sessionID := q.Get("session")

	length, err := h.service.QueueLen(sender, receiver, sessionID)
	if err != nil {
		grape.ExtractFromErr(ctx, w, fmt.Errorf("queue length: %w", err))
		return
	}

	grape.Respond(ctx, w, http.StatusOK, grape.Map{"length": length})
}

// BatchPopQueueHandler pops multiple messages from the queue in one request.
// Expects the same query parameters as PopQueueHandler plus an optional
// `limit` parameter (default 10, max 100).
func (h *Handler) BatchPopQueueHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	sender, err := grape.Query(q, "sender", model.ParsePublicKey)
	if err != nil {
		err = fmt.Errorf("parse sender: %w", err)
		grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErrMsg(err)))
		return
	}
	receiver, err := grape.Query(q, "receiver", model.ParsePublicKey)
	if err != nil {
		err = fmt.Errorf("parse receiver: %w", err)
		grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErrMsg(err)))
		return
	}
	sessionID := q.Get("session")
	limit := grape.QueryOrDefault(
		q, "limit", strconv.Atoi, services.DefaultBatchSize,
	)

	messages, err := h.service.BatchPopQueue(sender, receiver, sessionID, limit)
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
		encoded[i] = encodePayloadToBase64(msg)
	}

	grape.Respond(ctx, w, http.StatusOK, grape.Map{
		"data": encoded, "count": len(encoded),
	})
}
