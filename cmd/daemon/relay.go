package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/relayconn"
	"github.com/kamune-org/kamune/pkg/storage"
)

// defaultRelayTimeout bounds each relay registration and each relay dial,
// including a resume dial that tries several stored tokens: connecting to
// the relay, TLS, the HPKE exchange, PSK auth and the relay's Registered
// reply. It does not limit the connection after that.
const defaultRelayTimeout = 15 * time.Second

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
	app        *Daemon
	expiryOnce sync.Once
	expiryFn   func()
	dead       chan struct{}
	deadOnce   sync.Once
	sessionID  string
	consumed   atomic.Bool
}

type trackingConn struct {
	kamune.Conn
	tracker   *tokenTracker
	closeOnce sync.Once
	onClose   func()
}

func (c *trackingConn) AcceptedMeta() any { return c.tracker }

func (c *trackingConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		if c.onClose != nil {
			c.onClose()
		}
		err = c.Conn.Close()
	})
	return err
}

func (t *tokenTracker) Accept() (kamune.Conn, error) {
	cn, err := t.Listener.Accept()
	if err == nil {
		t.cancelExpiry()
		t.consumed.Store(true)
		t.app.markRelayTokenConsumed(t.token)
		return &trackingConn{
			Conn:    cn,
			tracker: t,
			onClose: func() {
				t.closeDead()
			},
		}, nil
	}
	t.closeDead()
	return nil, err
}

func (t *tokenTracker) Stop() {
	t.cancelExpiry()
	if !t.consumed.Load() {
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

// stampRelaySession records sessionID on the accepting tracker and on
// the slice entry that still points at it. Other tokens are left alone.
func stampRelaySession(
	tokens []relayToken, meta any, sessionID string,
) {
	tt, ok := meta.(*tokenTracker)
	if !ok || tt == nil {
		return
	}
	tt.sessionID = sessionID
	for i := range tokens {
		if tokens[i].listener == tt {
			tokens[i].sessionID = sessionID
		}
	}
}

func relaySessionID(tracker *tokenTracker, tokens []relayToken) string {
	if tracker != nil && tracker.sessionID != "" {
		return tracker.sessionID
	}
	for i := len(tokens) - 1; i >= 0; i-- {
		if tokens[i].sessionID != "" {
			return tokens[i].sessionID
		}
		tt, ok := tokens[i].listener.(*tokenTracker)
		if ok && tt.sessionID != "" {
			return tt.sessionID
		}
	}
	return ""
}

func loadRelayPool(
	store *storage.Storage, sessionID string,
) ([][]byte, bool) {
	if sessionID == "" || store == nil {
		return nil, false
	}
	m, err := store.GetMeta(sessionID, storage.RelayTokensKey)
	if err != nil || m.Value() == nil {
		return nil, false
	}
	return decodeTokenList(m.Value()), true
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

// listenRelayTracked registers with the relay at relayAddr, for at most
// a.relayTimeout, and returns a listener that tracks the token's expiry
// and use.
func listenRelayTracked(ctx context.Context, a *Daemon, relayAddr, password string, insecureSkipVerify bool, staticToken []byte) (kamune.Listener, string, time.Duration, time.Duration, error) {
	listener, tokenHex, ttl, sessionTTL, err := listenRelay(
		ctx, a.relayTimeout, relayAddr, password, insecureSkipVerify,
		staticToken,
	)
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

// listenRelay registers with the relay at relayAddr. Connecting and the
// relay handshake end after timeout, or when ctx does.
func listenRelay(
	ctx context.Context,
	timeout time.Duration,
	relayAddr, password string,
	insecureSkipVerify bool,
	staticToken []byte,
) (kamune.Listener, string, time.Duration, time.Duration, error) {
	if strings.TrimSpace(relayAddr) == "" {
		return nil, "", 0, 0, errors.New("relay server address is required")
	}

	opts := []relayconn.Option{relayconn.WithHandshakeTimeout(timeout)}
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
	return result.Listener, hex.EncodeToString(result.Token), result.TTL, result.SessionTTL, nil
}

func dialRelayFunc(relayAddr, tokenHex, password string, insecureSkipVerify bool) (func(string) (kamune.Conn, error), error) {
	return dialRelayFuncWithSessionTTL(
		context.Background(), defaultRelayTimeout,
		relayAddr, tokenHex, password, insecureSkipVerify, nil,
	)
}

// dialRelayFuncMultiToken returns a dial function that tries each of the given
// relay tokens in order, returning the first successful connection. All
// the tries together end after timeout, or when ctx does, so a stalled
// relay holds the dial for timeout however many tokens there are.
func dialRelayFuncMultiToken(
	ctx context.Context,
	timeout time.Duration,
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

	scheme, host, insecureOverride := parseRelayAddr(relayAddr)
	if insecureOverride != nil {
		insecureSkipVerify = *insecureOverride
	}

	return func(addr string) (kamune.Conn, error) {
		// The relay handshake ends when dctx does; the connection it
		// returns does not.
		dctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		var lastErr error
		for _, tok := range tokens {
			if dctx.Err() != nil {
				break
			}
			var (
				conn kamune.Conn
				err  error
			)
			opts := []relayconn.Option{
				relayconn.WithHandshakeTimeout(timeout),
			}
			if password != "" {
				opts = append(opts, relayconn.WithPassword(password))
			}
			tlsCfg := &tls.Config{InsecureSkipVerify: insecureSkipVerify}
			switch scheme {
			case "tcp":
				conn, err = relayconn.DialRelayTCP(dctx, host, tok, opts...)
			case "wss":
				conn, err = relayconn.DialRelayWSS(
					dctx, host, tok, tlsCfg, opts...,
				)
			case "tls":
				conn, err = relayconn.DialRelayTLS(
					dctx, host, tok, tlsCfg, opts...,
				)
			default:
				conn, err = relayconn.DialRelay(dctx, host, tok, opts...)
			}
			if err == nil {
				return conn, nil
			}
			lastErr = wrapRelayError(scheme, host, password != "", err)
		}
		if lastErr == nil {
			lastErr = wrapRelayError(scheme, host, password != "", dctx.Err())
		}
		return nil, lastErr
	}, nil
}

// dialRelayFuncWithSessionTTL returns a dial function that joins the relay
// session of tokenHex. Connecting and the relay handshake end after
// timeout, or when ctx does. When sessionTTL is not nil, the dial
// function stores the session TTL the relay reports in it.
func dialRelayFuncWithSessionTTL(
	ctx context.Context,
	timeout time.Duration,
	relayAddr, tokenHex, password string,
	insecureSkipVerify bool,
	sessionTTL *time.Duration,
) (func(string) (kamune.Conn, error), error) {
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

	scheme, host, insecureOverride := parseRelayAddr(relayAddr)
	if insecureOverride != nil {
		insecureSkipVerify = *insecureOverride
	}

	return func(addr string) (kamune.Conn, error) {
		opts := []relayconn.Option{relayconn.WithHandshakeTimeout(timeout)}
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
