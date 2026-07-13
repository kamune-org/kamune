package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/relayconn"
	"github.com/kamune-org/kamune/pkg/storage"
)

var errRelayCloseHint = errors.New("the relay server closed the connection — check the password and token")

func wrapRelayError(scheme, host string, password bool, err error) error {
	var hint string
	if strings.Contains(err.Error(), "received close frame") {
		hint = "; relay closed the connection"
		if password {
			hint += " — wrong password?"
		} else {
			hint += " — try providing a password or check the token"
		}
	}
	return fmt.Errorf("%s://%s%s: %w", scheme, host, hint, err)
}

type tokenTracker struct {
	kamune.Listener
	token      string
	ttl        time.Duration
	sessionTTL time.Duration
	expiresAt  time.Time
	app        *App
	expiryOnce sync.Once
	expiryFn   func()
	dead       chan struct{}
	deadOnce   sync.Once
	sessionID  string
	consumed   bool
}

func (t *tokenTracker) Accept() (kamune.Conn, error) {
	cn, err := t.Listener.Accept()
	if err == nil {
		t.cancelExpiry()
		t.consumed = true
		t.app.markRelayTokenConsumed(t.token)
	} else {
		t.closeDead()
	}
	return cn, err
}

func (t *tokenTracker) Stop() {
	t.cancelExpiry()
	if !t.consumed {
		t.closeDead()
	}
	if s, ok := t.Listener.(interface{ Stop() }); ok {
		s.Stop()
	}
}

func (t *tokenTracker) closeDead() {
	t.deadOnce.Do(func() { close(t.dead) })
}

func (t *tokenTracker) Dead() <-chan struct{} {
	return t.dead
}

func (t *tokenTracker) cancelExpiry() {
	t.expiryOnce.Do(func() {
		if t.expiryFn != nil {
			t.expiryFn()
		}
	})
}

func startExpiryTimer(t *tokenTracker) {
	if t.ttl <= 0 {
		return
	}
	timer := time.AfterFunc(t.ttl, func() {
		t.Stop()
		t.app.addLogEntry("INFO", "Relay token expired: "+t.token)
	})
	t.expiryFn = func() { timer.Stop() }
}

func listenRelayTracked(ctx context.Context, a *App, relayAddr, password string, insecureSkipVerify bool, staticToken []byte) (kamune.Listener, string, time.Duration, time.Duration, error) {
	listener, tokenHex, ttl, sessionTTL, err := listenRelay(ctx, relayAddr, password, insecureSkipVerify, staticToken)
	if err != nil {
		return nil, "", 0, 0, err
	}
	tracker := &tokenTracker{
		Listener:   listener,
		token:      tokenHex,
		ttl:        ttl,
		sessionTTL: sessionTTL,
		expiresAt:  time.Now().Add(ttl),
		app:        a,
		dead:       make(chan struct{}),
	}
	startExpiryTimer(tracker)
	return tracker, tokenHex, ttl, sessionTTL, nil
}

func parseRelayAddr(addr string) (scheme, host string, insecureOverride *bool) {
	addr = strings.TrimSpace(addr)
	for _, s := range []string{"tcp://", "ws://", "wss://", "tls://"} {
		if strings.HasPrefix(addr, s) {
			rest := addr[len(s):]
			scheme = strings.TrimSuffix(s, "://")
			host, insecureOverride = parseInsecureFlag(rest)
			return
		}
	}
	host, insecureOverride = parseInsecureFlag(addr)
	return "ws", host, insecureOverride
}

func parseInsecureFlag(s string) (host string, override *bool) {
	idx := strings.LastIndex(s, "?insecure=")
	if idx < 0 {
		return s, nil
	}
	val := s[idx+len("?insecure="):]
	host = s[:idx]
	switch val {
	case "true":
		v := true
		return host, &v
	case "false":
		v := false
		return host, &v
	}
	return s, nil
}

func listenRelay(ctx context.Context, relayAddr, password string, insecureSkipVerify bool, staticToken []byte) (kamune.Listener, string, time.Duration, time.Duration, error) {
	if strings.TrimSpace(relayAddr) == "" {
		return nil, "", 0, 0, errors.New("relay server address is required")
	}

	var opts []relayconn.Option
	if password != "" {
		opts = append(opts, relayconn.WithPassword(password))
	}
	if len(staticToken) > 0 {
		opts = append(opts, relayconn.WithToken(staticToken))
	}

	scheme, host, insecureOverride := parseRelayAddr(relayAddr)
	if insecureOverride != nil {
		insecureSkipVerify = *insecureOverride
	}

	var result *relayconn.ListenResult
	var err error
	switch scheme {
	case "tcp":
		result, err = relayconn.ListenRelayTCP(ctx, host, opts...)
	case "wss":
		result, err = relayconn.ListenRelayWSS(ctx, host, &tls.Config{InsecureSkipVerify: insecureSkipVerify}, opts...)
	case "tls":
		result, err = relayconn.ListenRelayTLS(ctx, host, &tls.Config{InsecureSkipVerify: insecureSkipVerify}, opts...)
	default:
		result, err = relayconn.ListenRelay(ctx, host, opts...)
	}
	if err != nil {
		return nil, "", 0, 0, wrapRelayError(scheme, host, password != "", err)
	}
	// For static tokens the relay returns the precomputed token; for
	// random mode it returns the assigned token. Either way, the
	// hex-encoded token is the token for display and for the dialer.
	return result.Listener, hex.EncodeToString(result.Token), result.TTL, result.SessionTTL, nil
}

func dialRelayFunc(relayAddr, tokenHex, password string, insecureSkipVerify bool) (func(string) (kamune.Conn, error), error) {
	return dialRelayFuncWithSessionTTL(relayAddr, tokenHex, password, insecureSkipVerify, nil)
}

// dialRelayFuncMultiToken returns a dial function that tries each of the given
// relay tokens in order, returning the first successful connection. The
// relay address is parsed once; only the token changes per attempt.
func dialRelayFuncMultiToken(
	relayAddr, password string,
	insecureSkipVerify bool,
	tokens [][]byte,
) (func(string) (kamune.Conn, error), error) {
	if strings.TrimSpace(relayAddr) == "" {
		return nil, errors.New("relay server address is required")
	}
	if len(tokens) == 0 {
		return nil, errors.New("at least one relay token is required")
	}

	ctx := context.Background()
	scheme, host, insecureOverride := parseRelayAddr(relayAddr)
	if insecureOverride != nil {
		insecureSkipVerify = *insecureOverride
	}

	return func(addr string) (kamune.Conn, error) {
		var lastErr error
		for _, rawToken := range tokens {
			var (
				conn kamune.Conn
				err  error
			)
			opts := []relayconn.Option{}
			if password != "" {
				opts = append(opts, relayconn.WithPassword(password))
			}
			switch scheme {
			case "tcp":
				conn, err = relayconn.DialRelayTCP(ctx, host, rawToken, opts...)
			case "wss":
				conn, err = relayconn.DialRelayWSS(ctx, host, rawToken, &tls.Config{InsecureSkipVerify: insecureSkipVerify}, opts...)
			case "tls":
				conn, err = relayconn.DialRelayTLS(ctx, host, rawToken, &tls.Config{InsecureSkipVerify: insecureSkipVerify}, opts...)
			default:
				conn, err = relayconn.DialRelay(ctx, host, rawToken, opts...)
			}
			if err == nil {
				return conn, nil
			}
			lastErr = wrapRelayError(scheme, host, password != "", err)
		}
		return nil, lastErr
	}, nil
}

func dialRelayFuncWithSessionTTL(relayAddr, tokenHex, password string, insecureSkipVerify bool, sessionTTL *time.Duration) (func(string) (kamune.Conn, error), error) {
	if strings.TrimSpace(relayAddr) == "" {
		return nil, errors.New("relay server address is required")
	}
	if strings.TrimSpace(tokenHex) == "" {
		return nil, errors.New("relay token is required")
	}

	token, err := hex.DecodeString(tokenHex)
	if err != nil {
		return nil, fmt.Errorf("decode token: %w", err)
	}

	ctx := context.Background()
	scheme, host, insecureOverride := parseRelayAddr(relayAddr)
	if insecureOverride != nil {
		insecureSkipVerify = *insecureOverride
	}

	return func(addr string) (kamune.Conn, error) {
		var opts []relayconn.Option
		if password != "" {
			opts = append(opts, relayconn.WithPassword(password))
		}
		var (
			conn kamune.Conn
			err  error
		)
		switch scheme {
		case "tcp":
			conn, err = relayconn.DialRelayTCP(ctx, host, token, opts...)
		case "wss":
			conn, err = relayconn.DialRelayWSS(ctx, host, token, &tls.Config{InsecureSkipVerify: insecureSkipVerify}, opts...)
		case "tls":
			conn, err = relayconn.DialRelayTLS(ctx, host, token, &tls.Config{InsecureSkipVerify: insecureSkipVerify}, opts...)
		default:
			conn, err = relayconn.DialRelay(ctx, host, token, opts...)
		}
		if err != nil {
			return nil, wrapRelayError(scheme, host, password != "", err)
		}
		if sessionTTL != nil {
			if rc, ok := conn.(*relayconn.RelayConn); ok {
				*sessionTTL = rc.SessionTTL()
			}
		}
		return conn, nil
	}, nil
}

// relayReconnectLoop monitors the relay listener for death and automatically
// re-registers with the next available token from the stored pool. It exits
// when the context is cancelled, the server stops, or the token pool is
// exhausted (cold-start required).
func (a *App) relayReconnectLoop(
	ctx context.Context, ml *multiListener,
) {
	const (
		minBackoff = 1 * time.Second
		maxBackoff = 5 * time.Second
	)

	// Find the current tracker's dead channel and session ID.
	a.mu.RLock()
	var currentDead <-chan struct{}
	var sessionID string
	for i := len(a.relayTokens) - 1; i >= 0; i-- {
		if tt, ok := a.relayTokens[i].listener.(*tokenTracker); ok {
			currentDead = tt.Dead()
			sessionID = tt.sessionID
			break
		}
	}
	a.mu.RUnlock()

	if currentDead == nil {
		slog.Warn("relay reconnect: no tracker found")
		return
	}

	for {
		// Wait for the current listener to die or context cancellation.
		select {
		case <-ctx.Done():
			return
		case <-currentDead:
		}

		// Jittered back-off before re-registering.
		jitter := time.Duration(
			rand.Int63n(int64(maxBackoff - minBackoff)),
		)
		select {
		case <-ctx.Done():
			return
		case <-time.After(minBackoff + jitter):
		}

		// Server stopped while we waited.
		a.mu.RLock()
		server := a.server
		a.mu.RUnlock()
		if server == nil {
			return
		}

		// Read stored ECDH tokens from BoltDB.
		st := a.store()
		if st == nil {
			return
		}
		m, err := st.GetMeta(
			sessionID, storage.RelayTokensKey,
		)
		if err != nil || m.Value() == nil {
			slog.Warn(
				"relay reconnect: no stored tokens, cold start required",
				"session", sessionID,
			)
			return
		}
		tokens := decodeTokenList(m.Value())
		if len(tokens) == 0 {
			slog.Warn(
				"relay reconnect: empty token pool, cold start required",
				"session", sessionID,
			)
			return
		}

		// Get relay connection config.
		a.mu.RLock()
		relayAddr := a.relayAddr
		password := a.relayPassword
		a.mu.RUnlock()

		// Try each token in the pool until one succeeds.
		var registered bool
		for _, token := range tokens {
			listener, tokenHex, ttl, sessTTL, listenErr :=
				listenRelayTracked(
					ctx, a, relayAddr, password,
					false, token,
				)
			if listenErr != nil {
				slog.Warn(
					"relay reconnect: attempt failed",
					"err", listenErr,
				)
				continue
			}
			if addErr := ml.Add(listener); addErr != nil {
				listener.Close()
				slog.Warn(
					"relay reconnect: add to multi-listener failed",
					"err", addErr,
				)
				continue
			}

			a.mu.Lock()
			a.relayTokens = append(a.relayTokens, relayToken{
				Token:      tokenHex,
				TTL:        ttl,
				SessionTTL: sessTTL,
				ExpiresAt:  time.Now().Add(ttl),
				Mode:       "ecdh",
				sessionID:  sessionID,
				listener:   listener,
			})
			a.mu.Unlock()

			slog.Info(
				"relay reconnect: listener re-registered",
				"token_prefix", tokenHex[:8],
			)

			// Track the new listener's death for the next cycle.
			if tt, ok := listener.(*tokenTracker); ok {
				currentDead = tt.Dead()
			}
			registered = true
			break
		}

		if !registered {
			slog.Warn(
				"relay reconnect: all tokens exhausted, cold start required",
				"session", sessionID,
				"pool_size", len(tokens),
			)
			runtime.EventsEmit(
				a.ctx, "relay-pool-exhausted", sessionID,
			)
			return
		}
	}
}
