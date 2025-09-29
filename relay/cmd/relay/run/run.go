package run

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hossein1376/grape/slogger"

	"github.com/kamune-org/kamune/relay/internal/config"
	"github.com/kamune-org/kamune/relay/internal/handlers"
	"github.com/kamune-org/kamune/relay/internal/services"
	"github.com/kamune-org/kamune/relay/internal/storage"
)

func Run() error {
	ctx := context.Background()

	var cfgPath string
	flag.StringVar(&cfgPath, "config", ".assets/config.toml", "config path")
	flag.Parse()

	slogger.NewDefault(slogger.WithLevel(slog.LevelDebug))
	cfg, err := config.New(cfgPath)
	if err != nil {
		return fmt.Errorf("new config: %w", err)
	}

	store, err := storage.Open(cfg.Storage)
	if err != nil {
		return fmt.Errorf("open storage: %w", err)
	}
	defer store.Close()

	srvc, err := services.New(store, cfg)
	if err != nil {
		return fmt.Errorf("new service: %w", err)
	}
	router := handlers.New(srvc)

	server := &http.Server{
		Addr:         cfg.Address,
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	errCh := make(chan error, 1)
	exitCh := make(chan os.Signal, 1)
	signal.Notify(exitCh, syscall.SIGINT)
	go func() {
		slog.Info("starting server", slog.String("address", server.Addr))
		if err := server.ListenAndServe(); err != nil {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("starting server: %w", err)
	case <-exitCh:
		slogger.Info(ctx, "received exit signal")
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			return fmt.Errorf("server shutdown: %w", err)
		}
		return nil
	}
}
