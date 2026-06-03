package handlers

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"

	"github.com/kamune-org/kamune/cmd/relay/internal/services"
)

func ServeTCP(hub *services.Hub, addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()

	slog.Info("tcp relay listening", slog.String("address", addr))

	for {
		conn, err := listener.Accept()
		if err != nil {
			slog.Error("tcp: accept failed", slog.Any("error", err))
			continue
		}

		adapter := &tcpAdapter{conn: conn, maxSize: hub.MaxMessageSize()}
		go handleRelayConn(context.Background(), hub, adapter, conn.RemoteAddr().String())
	}
}

func ServeTLS(hub *services.Hub, addr string, tlsCfg *tls.Config) error {
	listener, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		return err
	}
	defer listener.Close()

	slog.Info("tls relay listening", slog.String("address", addr))

	for {
		conn, err := listener.Accept()
		if err != nil {
			slog.Error("tls: accept failed", slog.Any("error", err))
			continue
		}

		adapter := &tlsAdapter{conn: conn, maxSize: hub.MaxMessageSize()}
		go handleRelayConn(context.Background(), hub, adapter, conn.RemoteAddr().String())
	}
}
