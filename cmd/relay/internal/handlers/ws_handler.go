package handlers

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"net/http"

	"github.com/coder/websocket"

	"github.com/kamune-org/kamune/cmd/relay/internal/services"
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
		slog.Error("ws: failed to accept", slog.Any("error", err))
		return
	}

	if maxSize := h.service.MaxMessageSize(); maxSize > 0 {
		conn.SetReadLimit(int64(maxSize))
	}

	adapter := &wsAdapter{conn: conn, ctx: ctx}
	remoteAddr := clientIP(r)
	handleRelayConn(ctx, h.service.Hub(), adapter, remoteAddr)
}

func handleRelayConn(
	ctx context.Context,
	hub *services.Hub,
	rw exchange.ReadWriter,
	remoteAddr string,
) {
	ch, err := exchange.Accept(rw)
	if err != nil {
		slog.Error("relay: hpke accept failed", slog.Any("error", err))
		return
	}

	needAuth := hub.Password() != ""

	frameBytes, err := ch.ReadBytes()
	if err != nil {
		ch.Close()
		return
	}
	var frame pb.Frame
	if err := proto.Unmarshal(frameBytes, &frame); err != nil {
		ch.Close()
		return
	}

	switch {
	case frame.GetAuth() != nil:
		if !needAuth {
			ch.Close()
			return
		}
		if subtle.ConstantTimeCompare(frame.GetAuth().GetPsk(), []byte(hub.Password())) != 1 {
			slog.Warn("relay: auth failed", slog.String("remote", remoteAddr))
			ch.Close()
			return
		}
		ack := &pb.Frame{Kind: &pb.Frame_Auth{Auth: &pb.Auth{}}}
		b, _ := proto.Marshal(ack)
		_ = ch.WriteBytes(b)

		frameBytes, err = ch.ReadBytes()
		if err != nil {
			ch.Close()
			return
		}
		if err := proto.Unmarshal(frameBytes, &frame); err != nil {
			ch.Close()
			return
		}

	case needAuth:
		slog.Warn("relay: missing auth frame", slog.String("remote", remoteAddr))
		ch.Close()
		return
	}

	register := frame.GetRegister()
	if register == nil {
		ch.Close()
		return
	}

	var token []byte

	if len(register.Token) == 0 {
		token, err = hub.RegisterListener(ch)
		if err != nil {
			slog.Error("relay: register listener", slog.Any("error", err))
			ch.Close()
			return
		}
	} else {
		token = register.Token
		err = hub.RegisterDialer(ch, token)
		if err != nil {
			slog.Error("relay: register dialer", slog.Any("error", err))
			ch.Close()
			return
		}
	}

	registered := &pb.Frame{
		Kind: &pb.Frame_Registered{
			Registered: &pb.Registered{Token: token},
		},
	}
	b, _ := proto.Marshal(registered)
	if err := ch.WriteBytes(b); err != nil {
		ch.Close()
		return
	}

	slog.Info("relay: peer registered",
		slog.String("remote", remoteAddr),
		slog.Bool("listener", len(register.Token) == 0),
	)

	hub.ReadPump(ctx, ch, token)
	hub.Unregister(token)
}
