package run

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kamune-org/kamune/cmd/relay/internal/broker"
	"github.com/kamune-org/kamune/cmd/relay/internal/config"
	"github.com/kamune-org/kamune/cmd/relay/internal/handlers"
	"github.com/kamune-org/kamune/cmd/relay/internal/ratelimit"
	"github.com/kamune-org/kamune/cmd/relay/internal/services"
)

func Run(cfgPath string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg, err := config.New(cfgPath)
	if err != nil {
		return fmt.Errorf("new config: %w", err)
	}
	level, err := cfg.Server.Level()
	if err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}
	slog.SetLogLoggerLevel(level)

	srvc, err := services.New(ctx, cfg)
	if err != nil {
		return fmt.Errorf("new service: %w", err)
	}
	warnSharedRateLimit(cfg)

	h := handlers.New(srvc, cfg)

	// Prepare fallible shared resources before launching any listener. This
	// keeps startup atomic: a bad later certificate or broker address cannot
	// leave an earlier HTTP or TCP listener running.
	certs := &certStore{dataDir: cfg.Server.DataDir}
	var tlsCfg *tls.Config
	if cfg.TLS.Enabled {
		tlsCfg, err = certs.serverConfig(
			"tls", cfg.TLS.CertFile, cfg.TLS.KeyFile,
		)
		if err != nil {
			return fmt.Errorf("load tls config: %w", err)
		}
	}

	var wssCfg *tls.Config
	if cfg.WSS.Enabled {
		wssCfg, err = certs.serverConfig(
			"wss", cfg.WSS.CertFile, cfg.WSS.KeyFile,
		)
		if err != nil {
			return fmt.Errorf("load wss config: %w", err)
		}
	}

	var br *broker.Broker
	if cfg.Broker.Enabled {
		br, err = newBroker(cfg)
		if err != nil {
			return fmt.Errorf("new broker: %w", err)
		}
	}

	errCh := make(chan error, 5)
	var wg sync.WaitGroup
	var httpServers []*http.Server

	// 1. Diagnose server (HTTP, /health only).
	if cfg.Diagnose.Enabled {
		mux := http.NewServeMux()
		mux.HandleFunc("/health", h.HealthHandler)
		diagnoseServer := &http.Server{
			Addr:              cfg.Diagnose.Address,
			Handler:           mux,
			ReadHeaderTimeout: 30 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
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
		wsMux.HandleFunc("/ws", h.WebSocketHandler)
	}
	if cfg.WS.Enabled {
		wsServer := newWSServer(cfg.WS.Address, wsMux, nil)
		httpServers = append(httpServers, wsServer)
		wg.Go(func() {
			slog.Info(
				"starting ws server", slog.String("address", wsServer.Addr),
			)
			if err := listenWS(wsServer, h); err != nil &&
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
		// wsMux is shared with [ws] when both are enabled.
		wssServer := newWSServer(cfg.WSS.Address, wsMux, wssCfg)
		httpServers = append(httpServers, wssServer)
		wg.Go(func() {
			slog.Info(
				"starting wss server", slog.String("address", wssServer.Addr),
			)
			if err := listenWS(wssServer, h); err != nil &&
				!errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("wss: %w", err)
			}
		})
	}

	// 6. Broker (UDP signaling). The socket is already bound, so a Run
	// error is a runtime failure, not a startup one. It is logged instead
	// of sent to errCh: a broker fault must not take down the TCP, TLS
	// and WS listeners.
	if br != nil {
		wg.Go(func() {
			slog.Info(
				"starting broker",
				slog.String("address", br.Addr().String()),
			)
			if err := br.Run(ctx); err != nil {
				slog.Error("broker stopped", slog.Any("error", err))
			}
		})
	}

	exitCh := make(chan os.Signal, 1)
	signal.Notify(exitCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(exitCh)

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

const (
	// wsRequestTimeout bounds reading a ws or wss request and writing a
	// response that is not an upgrade. WebSocketHandler clears both
	// deadlines on a connection it upgrades, so a session is not cut
	// short.
	wsRequestTimeout = 30 * time.Second
	// wsIdleTimeout closes an idle connection. Keep-alives are off, so it
	// is only a backstop.
	wsIdleTimeout = 60 * time.Second
	// wsMaxHeaderBytes caps a request's header block. An upgrade request,
	// even with a CDN's headers added, is a few KiB.
	wsMaxHeaderBytes = 32 << 10
)

// newWSServer returns the HTTP server for a [ws] listener, or for a [wss]
// listener when tlsCfg is set. Its one route, /ws, hijacks the connection
// on success, so a connection only ever needs one request: keep-alives are
// off and HTTP/2 is not offered. Without that, a client could keep a
// socket open indefinitely after a response, or send request after
// request on it. A failed TLS handshake is logged at debug, as a client
// can cause one per connection.
func newWSServer(
	addr string, handler http.Handler, tlsCfg *tls.Config,
) *http.Server {
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		TLSConfig:         tlsCfg,
		Protocols:         &protocols,
		ReadHeaderTimeout: wsRequestTimeout,
		ReadTimeout:       wsRequestTimeout,
		WriteTimeout:      wsRequestTimeout,
		IdleTimeout:       wsIdleTimeout,
		MaxHeaderBytes:    wsMaxHeaderBytes,
		ErrorLog:          handlers.HTTPErrorLog(),
	}
	srv.SetKeepAlivesEnabled(false)
	return srv
}

// proxiedListener is a ws or wss listener that may sit behind a proxy.
type proxiedListener struct {
	name, address string
}

// sharedRateLimitListeners returns the ws and wss listeners bound to a
// loopback, private or link-local address while the rate limiter is on and
// server.trusted_proxies is empty. That is how a relay behind a reverse
// proxy, CDN origin or tunnel such as cloudflared is usually set up. There,
// every connection comes from the proxy's address, so all clients share
// one quota, and a few requests from anyone lock everyone out.
func sharedRateLimitListeners(cfg config.Config) []proxiedListener {
	if !cfg.RateLimit.IsEnabled() || len(cfg.Server.TrustedProxies) > 0 {
		return nil
	}
	var found []proxiedListener
	for _, l := range []struct {
		proxiedListener
		enabled bool
	}{
		{proxiedListener{"ws", cfg.WS.Address}, cfg.WS.Enabled},
		{proxiedListener{"wss", cfg.WSS.Address}, cfg.WSS.Enabled},
	} {
		if l.enabled && privateBind(l.address) {
			found = append(found, l.proxiedListener)
		}
	}
	return found
}

// privateBind reports whether addr binds a loopback, private or link-local
// address rather than a public or unspecified one.
func privateBind(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

// warnSharedRateLimit logs a warning for each listener
// sharedRateLimitListeners returns.
func warnSharedRateLimit(cfg config.Config) {
	for _, l := range sharedRateLimitListeners(cfg) {
		slog.Warn(
			"listener is on a private address and "+
				"server.trusted_proxies is empty: if a proxy or tunnel "+
				"fronts it, all clients share the proxy's rate limit",
			slog.String("listener", l.name),
			slog.String("address", l.address),
		)
	}
}

// listenWS binds srv.Addr and serves srv on it with serveWS.
func listenWS(srv *http.Server, h *handlers.Handler) error {
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}
	return serveWS(srv, ln, h)
}

// serveWS serves srv on ln, over TLS when srv has a TLS config. Each
// connection from a direct peer is charged to its rate-limit key as it is
// accepted, before any TLS or HTTP work (see handlers.Handler.Listener).
// Serve closes ln when it returns.
func serveWS(srv *http.Server, ln net.Listener, h *handlers.Handler) error {
	ln = h.Listener(ln)
	if srv.TLSConfig != nil {
		return srv.ServeTLS(ln, "", "")
	}
	return srv.Serve(ln)
}

// newBroker binds the UDP broker with its own rate limiters.
func newBroker(cfg config.Config) (*broker.Broker, error) {
	return broker.New(cfg.Broker, newBrokerLimits(cfg.RateLimit))
}

// newBrokerLimits builds one limiter for echo and one for REGISTER from the
// [rate_limit] settings. Neither shares the hub's limiter: UDP source
// addresses are unverified, so spoofed packets would otherwise lock the named
// address out of TCP, TLS and WS. Echo and REGISTER do not share one either,
// so a spray of spoofed echoes cannot evict REGISTER histories.
func newBrokerLimits(rl config.RateLimit) broker.Limits {
	if !rl.IsEnabled() {
		return broker.Limits{}
	}
	newAllow := func() broker.AllowFunc {
		return ratelimit.New(
			int(rl.Quota), rl.TimeWindow, rl.MaxEntries,
		).Allow
	}
	return broker.Limits{Echo: newAllow(), Register: newAllow()}
}
