package handlers

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"net/http"
	"time"

	"github.com/coder/websocket"

	"github.com/kamune-org/kamune/cmd/relay/internal/services"
	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/relayconn/pb"
	"google.golang.org/protobuf/proto"
)

func (h *Handler) WebSocketHandler(w http.ResponseWriter, r *http.Request) {
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

	remoteAddr := clientIP(r)

	if rl := h.service.Hub().RateLimiter(); rl != nil && !rl.Allow(remoteAddr) {
		slog.Warn("rate limit exceeded", slog.String("remote", remoteAddr))
		conn.Close(websocket.StatusPolicyViolation, "rate limit exceeded")
		return
	}

	adapter := &wsAdapter{conn: conn, ctx: context.Background()}

	// Handshake timeout is enforced via a connection close, not via the
	// adapter context: the context would otherwise remain in effect for
	// the entire session and kill it after handshake_timeout.
	var handshakeTimer *time.Timer
	if timeout := h.service.Hub().HandshakeTimeout(); timeout > 0 {
		handshakeTimer = time.AfterFunc(timeout, func() {
			_ = conn.Close(websocket.StatusPolicyViolation, "handshake timeout")
		})
	}

	handleRelayConn(h.service.Hub(), adapter, remoteAddr, handshakeTimer)
}

func handleRelayConn(
	hub *services.Hub,
	rw exchange.ReadWriter,
	remoteAddr string,
	handshakeTimer *time.Timer,
) {
	stopHandshakeTimer := func() {
		if handshakeTimer != nil {
			handshakeTimer.Stop()
		}
	}
	defer stopHandshakeTimer()

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
	var ttlSeconds uint32
	var sessionTTLSeconds uint32

	if len(register.Token) == 0 {
		token, err = hub.RegisterListener(ch)
		if err != nil {
			slog.Error("relay: register listener", slog.Any("error", err))
			ch.Close()
			return
		}
		ttlSeconds = uint32(hub.TokenTTL().Seconds())
	} else {
		token = register.Token
		err = hub.RegisterDialer(ch, token)
		if err != nil {
			slog.Error("relay: register dialer", slog.Any("error", err))
			ch.Close()
			return
		}
	}
	sessionTTLSeconds = uint32(hub.SessionTTL().Seconds())

	registered := &pb.Frame{
		Kind: &pb.Frame_Registered{
			Registered: &pb.Registered{
				Token:             token,
				TtlSeconds:        ttlSeconds,
				SessionTtlSeconds: sessionTTLSeconds,
			},
		},
	}
	b, _ := proto.Marshal(registered)
	if err := ch.WriteBytes(b); err != nil {
		ch.Close()
		return
	}

	// Handshake completed successfully:
	//   - Stop the WS handshake timer (if any) so it does not fire later.
	//   - Clear the TCP/TLS connection deadline so it does not kill the
	//     session once registration is done. ch.SetDeadline is a no-op for
	//     the WS adapter, so this is safe for both transports.
	stopHandshakeTimer()
	_ = ch.SetDeadline(time.Time{})

	slog.Info("relay: peer registered",
		slog.String("remote", remoteAddr),
		slog.Bool("listener", len(register.Token) == 0),
	)

	hub.ReadPump(context.Background(), ch, token)
	hub.Unregister(token)
}
