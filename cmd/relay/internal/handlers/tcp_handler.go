package handlers

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"time"

	"github.com/kamune-org/kamune/cmd/relay/internal/services"
)

func acceptLoop(ctx context.Context, listener net.Listener, hub *services.Hub) {
	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	var tempDelay time.Duration
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if tempDelay == 0 {
				tempDelay = 5 * time.Millisecond
			} else {
				tempDelay *= 2
			}
			if tempDelay > time.Second {
				tempDelay = time.Second
			}
			slog.Error("accept failed", slog.Any("error", err))
			time.Sleep(tempDelay)
			continue
		}
		tempDelay = 0

		_ = setTCPKeepAlive(conn)

		adapter := newRawTCPAdapter(conn, hub.MaxMessageSize())
		remoteAddr := conn.RemoteAddr().String()

		if rl := hub.RateLimiter(); rl != nil &&
			!rl.Allow(rateLimitKey(extractIP(remoteAddr))) {
			logRateLimited(remoteAddr)
			conn.Close()
			continue
		}

		if timeout := hub.HandshakeTimeout(); timeout > 0 {
			conn.SetDeadline(time.Now().Add(timeout))
		}

		// TCP/TLS enforces the handshake timeout via the connection
		// deadline. The deadline is cleared inside handleRelayConn once
		// registration completes, so it does not apply to the session
		// lifetime. No timer is needed.
		go handleRelayConn(hub, adapter, remoteAddr, nil)
	}
}

func setTCPKeepAlive(conn net.Conn) error {
	switch c := conn.(type) {
	case *net.TCPConn:
		if err := c.SetKeepAlive(true); err != nil {
			return err
		}
		return c.SetKeepAlivePeriod(30 * time.Second)
	case *tls.Conn:
		return setTCPKeepAlive(c.NetConn())
	default:
		return nil
	}
}

func ServeTCP(ctx context.Context, hub *services.Hub, addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()

	slog.Info("tcp relay listening", slog.String("address", addr))
	acceptLoop(ctx, listener, hub)
	return nil
}

func ServeTLS(ctx context.Context, hub *services.Hub, addr string, tlsCfg *tls.Config) error {
	listener, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		return err
	}
	defer listener.Close()

	slog.Info("tls relay listening", slog.String("address", addr))
	acceptLoop(ctx, listener, hub)
	return nil
}
