package handlers

import (
	"errors"
	"fmt"
	"net/http"

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
	grape.Respond(ctx, w, http.StatusOK, grape.Map{"key": h.service.PublicKey()})
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

	// Attempt convey (direct delivery; will enqueue on failure)
	delivered, err := h.service.Convey(senderPK, receiverPK, req.SessionID, dataRaw)
	if err != nil {
		grape.ExtractFromErr(ctx, w, err)
		return
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

	grape.Respond(ctx, w, http.StatusCreated, grape.Map{"peer": peer})
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
