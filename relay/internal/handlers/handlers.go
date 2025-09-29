package handlers

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	"github.com/hossein1376/grape"
	"github.com/hossein1376/grape/errs"

	"github.com/kamune-org/kamune/pkg/attest"
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
	key := base64.RawURLEncoding.EncodeToString(h.service.PublicKey())
	grape.Respond(ctx, w, http.StatusOK, grape.Map{"key": key})
}

func (h *Handler) EchoIPHandler(w http.ResponseWriter, r *http.Request) {
	grape.Respond(r.Context(), w, http.StatusOK, grape.Map{"ip": userIP(r)})
}

type registerPeerRequest struct {
	PublicKey string          `json:"key"`
	Identity  attest.Identity `json:"identity"`
	Addr      string          `json:"address"`
}

func (h *Handler) RegisterPeerHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req registerPeerRequest
	err := grape.ReadJson(w, r, &req)
	if err != nil {
		grape.RespondFromErr(ctx, w, errs.BadRequest(err))
		return
	}
	pubKey := make([]byte, base64.RawURLEncoding.DecodedLen(len(req.PublicKey)))
	n, err := base64.RawURLEncoding.Decode(pubKey, []byte(req.PublicKey))
	if err != nil {
		grape.RespondFromErr(ctx, w, fmt.Errorf("decode public key: %w", err))
		return
	}
	peer, err := h.service.RegisterPeer(pubKey[:n], req.Identity, req.Addr)
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
	keyEncoded := []byte(r.URL.Query().Get("key"))
	if len(keyEncoded) == 0 {
		grape.RespondFromErr(ctx, w, errs.BadRequest(errors.New("key is empty")))
		return
	}
	key := make([]byte, base64.RawURLEncoding.DecodedLen(len(keyEncoded)))
	n, err := base64.RawURLEncoding.Decode(key, keyEncoded)
	if err != nil {
		grape.RespondFromErr(ctx, w, errs.BadRequest(err))
		return
	}
	peer, err := h.service.InquiryPeer(key[:n])
	if err != nil {
		grape.RespondFromErr(ctx, w, err)
		return
	}
	peer.ID = model.NewPeerID()

	grape.Respond(ctx, w, http.StatusOK, grape.Map{"peer": peer})
}

func (h *Handler) DiscardPeerHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	keyEncoded := []byte(r.URL.Query().Get("key"))
	if len(keyEncoded) == 0 {
		grape.RespondFromErr(ctx, w, errs.BadRequest(errors.New("key is empty")))
		return
	}
	key := make([]byte, base64.RawURLEncoding.DecodedLen(len(keyEncoded)))
	n, err := base64.RawURLEncoding.Decode(key, keyEncoded)
	if err != nil {
		grape.RespondFromErr(ctx, w, errs.BadRequest(err))
		return
	}

	err = h.service.DeletePeer(key[:n])
	if err != nil {
		grape.RespondFromErr(ctx, w, err)
		return
	}

	grape.Respond(ctx, w, http.StatusNoContent, nil)
}
