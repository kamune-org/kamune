package run

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/kamune-org/kamune/cmd/relay/internal/broker"
	"github.com/kamune-org/kamune/cmd/relay/internal/config"
	"github.com/kamune-org/kamune/cmd/relay/internal/handlers"
	"github.com/kamune-org/kamune/cmd/relay/internal/services"
)

func Run() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var cfgPath string
	flag.StringVar(&cfgPath, "c", "", "config file path (omit to use "+config.EnvKey+" env var)")
	flag.Parse()

	cfg, err := config.New(cfgPath)
	if err != nil {
		return fmt.Errorf("new config: %w", err)
	}

	srvc, err := services.New(ctx, cfg)
	if err != nil {
		return fmt.Errorf("new service: %w", err)
	}

	h := handlers.New(srvc, cfg)

	errCh := make(chan error, 5)
	var wg sync.WaitGroup
	var httpServers []*http.Server

	// 1. Diagnose server (HTTP, /health only).
	if cfg.Diagnose.Enabled {
		mux := http.NewServeMux()
		mux.HandleFunc("/health", h.HealthHandler)
		diagnoseServer := &http.Server{
			Addr:         cfg.Diagnose.Address,
			Handler:      mux,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
		}
		httpServers = append(httpServers, diagnoseServer)
		wg.Go(func() {
			slog.Info(
				"starting diagnose server",
				slog.String("address", diagnoseServer.Addr),
			)
			if err := diagnoseServer.ListenAndServe(); err != nil &&
				!errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("diagnose: %w", err)
			}
		})
	}

	// 2. Plain WS server. Build a single mux shared with the WSS
	// server below; the same /ws route is exposed on both addresses.
	var wsMux *http.ServeMux
	if cfg.WS.Enabled || cfg.WSS.Enabled {
		wsMux = http.NewServeMux()
		wsMux.HandleFunc("/ws", handlers.WebSocketHandlerNoMiddleware(srvc))
	}
	if cfg.WS.Enabled {
		wsServer := &http.Server{
			Addr:         cfg.WS.Address,
			Handler:      wsMux,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
		}
		httpServers = append(httpServers, wsServer)
		wg.Go(func() {
			slog.Info(
				"starting ws server", slog.String("address", wsServer.Addr),
			)
			if err := wsServer.ListenAndServe(); err != nil &&
				!errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("ws: %w", err)
			}
		})
	}

	// 3. Raw TCP server.
	if cfg.TCP.Enabled {
		wg.Go(func() {
			if err := handlers.ServeTCP(
				ctx, srvc.Hub(), cfg.TCP.Address,
			); err != nil {
				errCh <- fmt.Errorf("tcp: %w", err)
			}
		})
	}

	// 4. Raw TLS server (kamune-over-TLS).
	if cfg.TLS.Enabled {
		tlsCfg, err := loadTLSConfig(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			return fmt.Errorf("load tls config: %w", err)
		}
		wg.Go(func() {
			if err := handlers.ServeTLS(
				ctx, srvc.Hub(), cfg.TLS.Address, tlsCfg,
			); err != nil {
				errCh <- fmt.Errorf("tls: %w", err)
			}
		})
	}

	// 5. WSS server (WebSocket over TLS).
	if cfg.WSS.Enabled {
		wssCfg, err := loadTLSConfig(cfg.WSS.CertFile, cfg.WSS.KeyFile)
		if err != nil {
			return fmt.Errorf("load wss config: %w", err)
		}
		wssServer := &http.Server{
			Addr:         cfg.WSS.Address,
			Handler:      wsMux, // shared with [ws] when both are enabled
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			TLSConfig:    wssCfg,
		}
		httpServers = append(httpServers, wssServer)
		wg.Go(func() {
			slog.Info(
				"starting wss server", slog.String("address", wssServer.Addr),
			)
			if err := wssServer.ListenAndServeTLS("", ""); err != nil &&
				!errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("wss: %w", err)
			}
		})
	}

	// 6. Broker (UDP signaling).
	var br *broker.Broker
	if cfg.Broker.Enabled {
		var allow broker.AllowFunc
		if rl := srvc.Hub().RateLimiter(); rl != nil {
			allow = rl.Allow
		}
		br, err = broker.New(cfg.Broker, allow)
		if err != nil {
			return fmt.Errorf("new broker: %w", err)
		}
		wg.Go(func() {
			slog.Info(
				"starting broker",
				slog.String("address", cfg.Broker.Address),
			)
			if err := br.Run(ctx); err != nil {
				errCh <- fmt.Errorf("broker: %w", err)
			}
		})
	}

	exitCh := make(chan os.Signal, 1)
	signal.Notify(exitCh, syscall.SIGINT, syscall.SIGTERM)

	// shutdown is the canonical teardown sequence used by both the
	// signal path and the startup-error path. It cancels the context
	// (which unblocks acceptLoop goroutines for TCP/TLS), shuts down
	// every http.Server in turn, and waits for all goroutines to exit.
	shutdown := func() error {
		cancel()
		if br != nil {
			_ = br.Close()
		}
		var errs []error
		for _, srv := range httpServers {
			shutdownCtx, shutdownCancel := context.WithTimeout(
				context.Background(), 5*time.Second,
			)
			if err := srv.Shutdown(shutdownCtx); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", srv.Addr, err))
			}
			shutdownCancel()
		}
		wg.Wait()
		return errors.Join(errs...)
	}

	select {
	case err := <-errCh:
		if sErr := shutdown(); sErr != nil {
			slog.Error("shutdown after startup failure", slog.Any("error", sErr))
		}
		return fmt.Errorf("starting server: %w", err)
	case sig := <-exitCh:
		slog.Info("shutting down", slog.String("signal", sig.String()))
		if err := shutdown(); err != nil {
			return err
		}
		return nil
	}
}

func loadTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	if certFile == "" && keyFile == "" {
		return generateSelfSignedCertInMemory()
	}

	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf(
			"load tls cert from %q and %q: %w "+
				"(generate one with `openssl req -x509 ...`)",
			certFile, keyFile, err,
		)
	}
	return &tls.Config{Certificates: []tls.Certificate{pair}}, nil
}

func generateSelfSignedCertInMemory() (*tls.Config, error) {
	certPEM, keyPEM, err := createSelfSignedCert()
	if err != nil {
		return nil, fmt.Errorf("generate self-signed cert: %w", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse self-signed cert: %w", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}

func createSelfSignedCert() (certPEM, keyPEM []byte, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}

	// 128-bit cryptographically random serial, as recommended by
	// RFC 5280 §4.1.2.2. Avoids collisions when the same process
	// generates multiple certs within the same nanosecond.
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "Kamune Relay",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(
		rand.Reader, &template, &template, &priv.PublicKey, priv,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("create cert: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: privBytes},
	)
	return certPEM, keyPEM, nil
}
