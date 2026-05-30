package handlers

import (
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/google/uuid"
	"github.com/hossein1376/grape"
	"github.com/hossein1376/grape/errs"

	"github.com/kamune-org/kamune/cmd/relay/internal/config"
	"github.com/kamune-org/kamune/cmd/relay/internal/model"
	"github.com/kamune-org/kamune/cmd/relay/internal/services"
)

type Handler struct {
	service *services.Service
}

func New(service *services.Service, cfg config.Config) *grape.Router {
	h := &Handler{service: service}
	return newRouter(h, cfg)
}

// WebSocketHandler returns the WebSocket handler without grape middleware,
// so that http.Hijacker is preserved for the WebSocket upgrade.
//   - TODO: remove this function when grape releases v0.7.0+ (respWriter
//     implements http.Hijacker). After that, register /ws through the
//     grape router as before.
func WebSocketHandler(service *services.Service) http.HandlerFunc {
	return (&Handler{service: service}).WebSocketHandler
}

func (h *Handler) HealthHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	status, err := h.service.Health()
	if err != nil {
		grape.Respond(
			ctx, w, http.StatusServiceUnavailable, grape.Map{"health": status},
		)
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

	req, err := grape.ReadValidateJSON[conveyRequest](w, r)
	if err != nil {
		grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErrMsg(err)))
		return
	}

	dataRaw, err := decodeBase64Raw(req.Data)
	if err != nil {
		err = fmt.Errorf("data: %w", err)
		grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErrMsg(err)))
		return
	}

	// Attempt convey with WebSocket delivery first, then HTTP, then queue.
	delivered, err := h.service.ConveyWithWS(
		ctx, req.Sender, req.Receiver, req.SessionID, dataRaw,
	)
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
	req, err := grape.ReadJSON[registerPeerRequest](w, r)
	if err != nil {
		grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErrMsg(err)))
		return
	}
	addr := make([]string, len(req.Addr)+1)
	copy(addr, req.Addr)
	addr[len(req.Addr)] = clientIP(r)

	for _, ip := range req.Addr {
		if parsed := net.ParseIP(ip); parsed == nil {
			err = fmt.Errorf("invalid ip: %s", ip)
			grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErrMsg(err)))
			return
		}
	}

	peer, err := h.service.RegisterPeer(req.PublicKey, addr)
	if err != nil {
		if errors.Is(err, services.ErrExistingPeer) {
			peer.ID = model.EmptyPeerID()
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

func (h *Handler) InquiryPeerHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	key, err := grape.Query(r.URL.Query(), "key", model.ParsePublicKey)
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
	id, err := grape.Param(r, "id", uuid.Parse)
	if err != nil {
		grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErrMsg(err)))
		return
	}

	err = h.service.DeletePeer(model.PeerID(id))
	if err != nil {
		grape.ExtractFromErr(ctx, w, err)
		return
	}

	grape.Respond(ctx, w, http.StatusNoContent, nil)
}

// RefreshPeerHandler renews the TTL of an existing peer registration.
// The caller provides their public key (as base64 query param `key`) and
// optionally a JSON body with updated addresses.
func (h *Handler) RefreshPeerHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := grape.Param(r, "id", uuid.Parse)
	if err != nil {
		grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErrMsg(err)))
		return
	}
	key, err := grape.Query(r.URL.Query(), "key", model.ParsePublicKey)
	if err != nil {
		grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErrMsg(err)))
		return
	}

	// Optionally read new addresses from the body.
	var newAddr []string
	if r.ContentLength > 0 {
		req, err := grape.ReadJSON[refreshRequest](w, r)
		if err != nil {
			grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErrMsg(err)))
			return
		}
		if req != nil {
			newAddr = req.Addr
		}
	}

	peer, err := h.service.RefreshPeer(model.PeerID(id), key, newAddr)
	if err != nil {
		grape.ExtractFromErr(ctx, w, err)
		return
	}

	if m := h.service.Metrics(); m != nil {
		m.IncPeersRefreshed()
	}

	grape.Respond(ctx, w, http.StatusOK, grape.Map{"peer": peer})
}

// RegisterWebhookHandler registers a webhook callback URL for a peer.
// When a message arrives for that peer and is enqueued, the relay will POST
// a JSON notification to the provided URL.
func (h *Handler) RegisterWebhookHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	req, err := grape.ReadValidateJSON[webhookRequest](w, r)
	if err != nil {
		grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErrMsg(err)))
		return
	}

	h.service.RegisterWebhook(req.PublicKey, req.URL)
	grape.Respond(ctx, w, http.StatusNoContent, nil)
}

// UnregisterWebhookHandler removes a webhook registration for a peer.
func (h *Handler) UnregisterWebhookHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	peer, err := grape.Query(r.URL.Query(), "key", model.ParsePublicKey)
	if err != nil {
		grape.ExtractFromErr(ctx, w, errs.BadRequest(errs.WithErrMsg(err)))
		return
	}

	if removed := h.service.UnregisterWebhook(peer); !removed {
		err = errors.New("no webhook registered for this key")
		grape.ExtractFromErr(ctx, w, errs.NotFound(errs.WithErrMsg(err)))
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
	grape.Respond(
		r.Context(), w, http.StatusNotFound, grape.Map{"error": "metrics not available"},
	)
}
