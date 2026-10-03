package handlers

import (
	"crypto/subtle"
	"io"
	"log/slog"
	"math"
	"net/http"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/kamune-org/kamune/cmd/relay/internal/services"
	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/relayconn/pb"
	"google.golang.org/protobuf/proto"
)

const (
	handshakePending int32 = iota
	handshakeFinished
	handshakeTimedOut
)

// claimHandshake moves a pending handshake to next. Only one caller wins.
func claimHandshake(state *atomic.Int32, next int32) bool {
	return state.CompareAndSwap(handshakePending, next)
}

func (h *Handler) WebSocketHandler(w http.ResponseWriter, r *http.Request) {
	remoteAddr := clientIP(r, h.trustedProxies)
	if rl := h.service.Hub().RateLimiter(); rl != nil && !rl.Allow(remoteAddr) {
		slog.Warn("rate limit exceeded", slog.String("remote", remoteAddr))
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		slog.Error("ws: failed to accept", slog.Any("error", err))
		return
	}

	maxSize := h.service.MaxMessageSize()
	if maxSize > 0 {
		conn.SetReadLimit(int64(maxSize))
	} else {
		conn.SetReadLimit(math.MaxUint16)
	}

	adapter := &wsAdapter{conn: conn}

	// Handshake timeout is enforced via a connection close, not via the
	// adapter context: the context would otherwise remain in effect for
	// the entire session and kill it after handshake_timeout.
	// Completion and timeout share one claim. Stop's return value is
	// not the decision: a callback that already passed a load can still
	// close a session the handler has finished.
	var handshakeTimer *time.Timer
	var handshakeState atomic.Int32
	if timeout := h.service.Hub().HandshakeTimeout(); timeout > 0 {
		handshakeTimer = time.AfterFunc(timeout, func() {
			if claimHandshake(&handshakeState, handshakeTimedOut) {
				_ = conn.Close(
					websocket.StatusPolicyViolation,
					"handshake timeout",
				)
			}
		})
	}
	cancelHandshake := func() {
		if !claimHandshake(&handshakeState, handshakeFinished) {
			return
		}
		if handshakeTimer != nil {
			handshakeTimer.Stop()
		}
	}

	handleRelayConn(h.service.Hub(), adapter, remoteAddr, cancelHandshake)
}

func handleRelayConn(
	hub *services.Hub,
	rw exchange.ReadWriter,
	remoteAddr string,
	cancelHandshake func(),
) {
	// ch is hoisted to function scope so the panic-recovery defer below
	// can close it regardless of where the panic occurred.
	var ch *exchange.Channel
	var registeredToken []byte

	defer func() {
		if r := recover(); r != nil {
			slog.Error("relay: panic in handler",
				slog.Any("error", r),
				slog.String("remote", remoteAddr),
				slog.String("stack", string(debug.Stack())),
			)
		}
		// Close the peer first while the session is still registered,
		// then drop the map entry. Closing the adapter last covers
		// panics that occur before ch is assigned.
		if len(registeredToken) > 0 {
			hub.ClosePeerChannel(registeredToken, ch)
			hub.Unregister(registeredToken, ch)
		}
		if ch != nil {
			_ = ch.Close()
		}
		if closer, ok := rw.(io.Closer); ok {
			_ = closer.Close()
		}
		if cancelHandshake != nil {
			cancelHandshake()
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
			ttlSeconds = durationSeconds(hub.TokenTTL())
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
			ttlSeconds = durationSeconds(hub.TokenTTL())
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
	sessionTTLSeconds = durationSeconds(hub.SessionTTL())
	registeredToken = sentToken

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
	//   - Claim the handshake as finished and stop its timer. A timeout
	//     callback that already won the claim does not get here, and the
	//     defer's later call loses the claim and does not stop again.
	//   - Clear the TCP/TLS connection deadline so it does not kill the
	//     session once registration is done. ch.SetDeadline is a no-op for
	//     the WS adapter, so this is safe for both transports.
	if cancelHandshake != nil {
		cancelHandshake()
	}
	_ = ch.SetDeadline(time.Time{})

	slog.Info("relay: peer registered",
		slog.String("remote", remoteAddr),
		slog.Bool("listener", mode == pb.Register_MODE_CREATE),
	)

	hub.ReadPump(ch, sentToken)
}

func durationSeconds(d time.Duration) uint32 {
	if d <= 0 {
		return 0
	}
	s := math.Ceil(d.Seconds())
	if s > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(s)
}
