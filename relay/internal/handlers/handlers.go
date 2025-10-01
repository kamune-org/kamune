package handlers

import (
	"errors"
	"net/http"

	"github.com/hossein1376/grape"
	"github.com/hossein1376/grape/errs"

	"github.com/kamune-org/kamune/relay/internal/model"
	"github.com/kamune-org/kamune/relay/internal/services"
)

type Handler struct {
	service *services.Service
}

func New(service *services.Service) *grape.Router {
	h := &Handler{service: service}
	return newRouter(h)
}

func (h *Handler) IdentityHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	grape.Respond(ctx, w, http.StatusOK, grape.Map{"key": h.service.PublicKey()})
}

func (h *Handler) EchoIPHandler(w http.ResponseWriter, r *http.Request) {
	grape.Respond(r.Context(), w, http.StatusOK, grape.Map{"ip": userIP(r)})
}

func (h *Handler) RegisterPeerHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	req, err := registerPeerBinder(w, r)
	if err != nil {
		grape.RespondFromErr(ctx, w, errs.BadRequest(err))
		return
	}
	peer, err := h.service.RegisterPeer(req.publicKey, req.Identity, req.Addr)
	if err != nil {
		if errors.Is(err, services.ErrExistingPeer) {
			peer.ID = model.NewPeerID()
			grape.Respond(ctx, w, http.StatusConflict, grape.Map{"peer": peer})
			return
		}
		grape.RespondFromErr(ctx, w, err)
		return
	}

	grape.Respond(ctx, w, http.StatusCreated, grape.Map{"peer": peer})
}

func (h *Handler) InquiryPeerHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	key, err := readKeyFromQuery(r.URL.Query())
	if err != nil {
		grape.RespondFromErr(ctx, w, errs.BadRequest(err))
		return
	}
	peer, err := h.service.InquiryPeer(key)
	if err != nil {
		grape.RespondFromErr(ctx, w, err)
		return
	}
	peer.ID = model.NewPeerID() // remove peer id from response

	grape.Respond(ctx, w, http.StatusOK, grape.Map{"peer": peer})
}

func (h *Handler) DiscardPeerHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	key, err := readKeyFromQuery(r.URL.Query())
	if err != nil {
		grape.RespondFromErr(ctx, w, errs.BadRequest(err))
		return
	}
	err = h.service.DeletePeer(key)
	if err != nil {
		grape.RespondFromErr(ctx, w, err)
		return
	}

	grape.Respond(ctx, w, http.StatusNoContent, nil)
}
