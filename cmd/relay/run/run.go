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
	"path/filepath"
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
	flag.StringVar(&cfgPath, "config", "assets/config.toml", "config path")
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

	select {
	case err := <-errCh:
		cancel()
		return fmt.Errorf("starting server: %w", err)
	case sig := <-exitCh:
		slog.Info("shutting down", slog.String("signal", sig.String()))
		cancel()
		if server != nil {
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			if err := server.Shutdown(shutdownCtx); err != nil {
				return fmt.Errorf("server shutdown: %w", err)
			}
		}
		wg.Wait()
		return nil
	}
}

func loadTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	if certFile == "" {
		certFile = "assets/cert/server.crt"
	}
	if keyFile == "" {
		keyFile = "assets/cert/server.key"
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err == nil {
		return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
	}

	slog.Warn("tls cert files not found, generating self-signed certificate",
		slog.String("cert", certFile),
		slog.String("key", keyFile),
	)

	cert, err = generateSelfSignedCert(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("generate self-signed cert: %w", err)
	}

	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}

func generateSelfSignedCert(certFile, keyFile string) (tls.Certificate, error) {
	if err := os.MkdirAll(filepath.Dir(certFile), 0755); err != nil {
		return tls.Certificate{}, fmt.Errorf("create cert dir: %w", err)
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: new(big.Int).SetUint64(uint64(time.Now().UnixNano())),
		Subject: pkix.Name{
			CommonName: "Kamune Relay",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})

	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		return tls.Certificate{}, fmt.Errorf("write cert: %w", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		return tls.Certificate{}, fmt.Errorf("write key: %w", err)
	}

	return tls.X509KeyPair(certPEM, keyPEM)
}
