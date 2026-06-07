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

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			slog.Error("accept failed", slog.Any("error", err))
			continue
		}

		adapter := &rawTCPAdapter{conn: conn, maxSize: hub.MaxMessageSize()}
		remoteAddr := conn.RemoteAddr().String()

		if rl := hub.RateLimiter(); rl != nil && !rl.Allow(extractIP(remoteAddr)) {
			slog.Warn("rate limit exceeded", slog.String("remote", remoteAddr))
			conn.Close()
			continue
		}

		if timeout := hub.HandshakeTimeout(); timeout > 0 {
			conn.SetDeadline(time.Now().Add(timeout))
		}

		go handleRelayConn(hub, adapter, remoteAddr)
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
