package handlers

import (
	"context"
	"encoding/base64"
	"log/slog"
	"net/http"

	"github.com/coder/websocket"
	"github.com/hossein1376/grape/slogger"

	"github.com/kamune-org/kamune/cmd/relay/internal/model"
	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/relayconn/pb"
	"google.golang.org/protobuf/proto"
)

func (h *Handler) WebSocketHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		slog.Error("ws: failed to accept", slogger.Err("err", err))
		return
	}

	if maxSize := h.service.MaxMessageSize(); maxSize > 0 {
		conn.SetReadLimit(int64(maxSize))
	}

	adapter := &wsAdapter{conn: conn, ctx: ctx}
	ch, err := exchange.Accept(adapter)
	if err != nil {
		conn.Close(websocket.StatusNormalClosure, "exchange failed")
		slog.Error("ws: hpke accept failed", slogger.Err("err", err))
		return
	}

	identityBytes, err := ch.ReadBytes()
	if err != nil {
		ch.Close()
		return
	}
	var identityFrame pb.Frame
	if err := proto.Unmarshal(identityBytes, &identityFrame); err != nil {
		ch.Close()
		return
	}
	peerKey := identityFrame.GetIdentity().GetKey()
	if len(peerKey) == 0 {
		ch.Close()
		return
	}

	pk := model.PublicKey(base64.RawURLEncoding.EncodeToString(peerKey))

	relayFrame := &pb.Frame{
		Kind: &pb.Frame_Identity{
			Identity: &pb.Identity{Key: h.service.PublicKeyRaw()},
		},
	}
	relayBytes, _ := proto.Marshal(relayFrame)
	if err := ch.WriteBytes(relayBytes); err != nil {
		ch.Close()
		return
	}

	hub := h.service.Hub()
	if hub == nil {
		_ = ch.Close()
		return
	}

	connCtx, cancel := context.WithCancel(ctx)
	hub.Register(pk, ch, cancel)

	if m := h.service.Metrics(); m != nil {
		m.IncWSConnections()
	}

	slog.Info(
		"ws: peer connected",
		slogger.String("peer", pk),
		slog.String("remote", clientIP(r)),
	)

	hub.ReadPump(connCtx, pk, ch, func(msgCtx context.Context, msg *pb.Message) error {
		if m := h.service.Metrics(); m != nil {
			m.IncWSMessagesIn()
		}
		err := h.service.HandleWSRelay(msgCtx, pk, msg)
		if err == nil {
			if m := h.service.Metrics(); m != nil {
				m.IncWSMessagesOut()
			}
		}
		return err
	})

	hub.Unregister(pk)
	if m := h.service.Metrics(); m != nil {
		m.DecWSConnections()
	}

	slog.Info("ws: peer disconnected", slogger.String("peer", pk))
}
