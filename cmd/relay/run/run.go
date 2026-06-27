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

	"github.com/kamune-org/kamune/cmd/relay/internal/config"
	"github.com/kamune-org/kamune/cmd/relay/internal/handlers"
	"github.com/kamune-org/kamune/cmd/relay/internal/services"
)

func Run() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var cfgPath string
	flag.StringVar(&cfgPath, "c", "config.toml", "config path")
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

	if !cfg.WS.Enabled && !cfg.TCP.Enabled && !cfg.TLS.Enabled {
		return fmt.Errorf("no transport enabled (enable ws, tcp, or tls)")
	}

	errCh := make(chan error, 3)
	var wg sync.WaitGroup

	// TCP listener
	if cfg.TCP.Enabled {
		wg.Go(func() {
			err := handlers.ServeTCP(ctx, srvc.Hub(), cfg.TCP.Address)
			if err != nil {
				errCh <- err
			}
		})
	}

	// TLS listener + TLS config for HTTP/WS
	var tlsCfg *tls.Config
	if cfg.TLS.Enabled {
		tlsCfg, err = loadTLSConfig(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			return fmt.Errorf("load tls config: %w", err)
		}

		wg.Go(func() {
			err := handlers.ServeTLS(ctx, srvc.Hub(), cfg.TLS.Address, tlsCfg)
			if err != nil {
				errCh <- err
			}
		})
	}

	// HTTP/WS server
	var server *http.Server
	if cfg.WS.Enabled {
		mux := http.NewServeMux()
		if cfg.Server.ExposeHealth {
			mux.HandleFunc("/health", h.HealthHandler)
		}
		if cfg.Server.ExposeIP {
			mux.HandleFunc("/ip", h.EchoIPHandler)
		}
		mux.HandleFunc("/ws", handlers.WebSocketHandlerNoMiddleware(srvc))

		server = &http.Server{
			Addr:         cfg.Server.Address,
			Handler:      mux,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
		}

		wg.Go(func() {
			slog.Info("starting http relay", slog.String("address", server.Addr))
			if tlsCfg != nil {
				server.TLSConfig = tlsCfg
				err := server.ListenAndServeTLS("", "")
				if err != nil && !errors.Is(err, http.ErrServerClosed) {
					errCh <- err
				}
			} else {
				err := server.ListenAndServe()
				if err != nil && !errors.Is(err, http.ErrServerClosed) {
					errCh <- err
				}
			}
		})
	}

	exitCh := make(chan os.Signal, 1)
	signal.Notify(exitCh, syscall.SIGINT, syscall.SIGTERM)

	// shutdown is the canonical teardown sequence used by both the
	// signal path and the startup-error path. It cancels the context
	// (which unblocks acceptLoop goroutines for TCP/TLS), shuts down
	// the HTTP server (which unblocks ListenAndServe), and waits for
	// every goroutine to exit.
	shutdown := func() error {
		cancel()
		if server != nil {
			shutdownCtx, shutdownCancel := context.WithTimeout(
				context.Background(), 5*time.Second,
			)
			defer shutdownCancel()
			if err := server.Shutdown(shutdownCtx); err != nil {
				return fmt.Errorf("server shutdown: %w", err)
			}
		}
		wg.Wait()
		return nil
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
