package handlers

import (
	"crypto/subtle"
	"io"
	"log/slog"
	"net/http"
	"runtime/debug"
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

	adapter := &wsAdapter{conn: conn}

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
	// ch is hoisted to function scope so the panic-recovery defer below
	// can close it regardless of where the panic occurred.
	var ch *exchange.Channel

	defer func() {
		if r := recover(); r != nil {
			slog.Error("relay: panic in handler",
				slog.Any("error", r),
				slog.String("remote", remoteAddr),
				slog.String("stack", string(debug.Stack())),
			)
		}
		// Best-effort cleanup so the underlying connection is closed and
		// the peer's read pump exits even if a panic bypassed the normal
		// error paths. We close the adapter (if it implements io.Closer)
		// in addition to the exchange channel, so a panic that occurs
		// before ch is assigned still results in a closed connection.
		if ch != nil {
			_ = ch.Close()
		}
		if closer, ok := rw.(io.Closer); ok {
			_ = closer.Close()
		}
		if handshakeTimer != nil {
			handshakeTimer.Stop()
		}
	}()

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

	var (
		sentToken         []byte
		ttlSeconds        uint32
		sessionTTLSeconds uint32
	)

	mode := register.GetMode()
	token := register.GetToken()

	switch mode {
	case pb.Register_MODE_CREATE:
		if len(token) == 0 {
			sentToken, err = hub.RegisterListener(ch)
			if err != nil {
				slog.Error(
					"relay: register listener",
					slog.Any("error", err),
				)
				ch.Close()
				return
			}
			ttlSeconds = uint32(hub.TokenTTL().Seconds())
		} else {
			if err := hub.RegisterListenerWith(ch, token); err != nil {
				slog.Error(
					"relay: register listener with token",
					slog.Any("error", err),
				)
				ch.Close()
				return
			}
			sentToken = token
			ttlSeconds = uint32(hub.TokenTTL().Seconds())
		}

	case pb.Register_MODE_JOIN:
		if len(token) == 0 {
			slog.Warn(
				"relay: join without token",
				slog.String("remote", remoteAddr),
			)
			ch.Close()
			return
		}
		if err = hub.RegisterDialer(ch, token); err != nil {
			slog.Error("relay: register dialer", slog.Any("error", err))
			ch.Close()
			return
		}
		sentToken = token

	default: // MODE_UNSPECIFIED
		slog.Warn(
			"relay: unspecified register mode",
			slog.String("remote", remoteAddr),
		)
		ch.Close()
		return
	}
	sessionTTLSeconds = uint32(hub.SessionTTL().Seconds())

	registered := &pb.Frame{
		Kind: &pb.Frame_Registered{
			Registered: &pb.Registered{
				Token:             sentToken,
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
	//     The defer at the top of the function is a safety net for the
	//     panic path; Stop is idempotent.
	//   - Clear the TCP/TLS connection deadline so it does not kill the
	//     session once registration is done. ch.SetDeadline is a no-op for
	//     the WS adapter, so this is safe for both transports.
	if handshakeTimer != nil {
		handshakeTimer.Stop()
	}
	_ = ch.SetDeadline(time.Time{})

	slog.Info("relay: peer registered",
		slog.String("remote", remoteAddr),
		slog.Bool("listener", mode == pb.Register_MODE_CREATE),
	)

	hub.ReadPump(ch, sentToken)
	hub.Unregister(sentToken)
}
