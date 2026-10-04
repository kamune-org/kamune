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

// defaultRelayResumeWindow bounds how long after a relay session drops
// the server registers listeners for its peer to resume it on. A daemon
// or bus dialer gives up reconnecting well within it.
const defaultRelayResumeWindow = 10 * time.Minute

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

// relayExpirySlack is how long before its expiry a relay token's link may
// end and still count as expired: the relay drops an expired token on
// its own clock, which runs a little ahead of the daemon's.
const relayExpirySlack = 5 * time.Second

type tokenTracker struct {
	kamune.Listener
	token      string
	ttl        time.Duration
	sessionTTL time.Duration
	expiresAt  time.Time
	app        *Daemon
	// expiryMu guards expiry, the timer that stops the listener once the
	// token expires.
	expiryMu sync.Mutex
	expiry   *time.Timer
	dead     chan struct{}
	deadOnce sync.Once
	// sessionID is the session that ran on the token's connection. It is
	// written and read under app.mu.
	sessionID string
	// resumeOf is the session that the token was registered for, so
	// that its peer can resume it, or empty. It is set before the
	// listener is in use and not changed after.
	resumeOf string
	consumed atomic.Bool
	// stopping is set once the daemon stops or closes the listener.
	stopping atomic.Bool
	// removed is set, before the listener is closed, when the user
	// removed the token: no listener is registered again for resumeOf.
	removed atomic.Bool
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
	if t.linkLost() {
		t.app.relayLinkLost(t)
	}
	return nil, err
}

// linkLost reports whether the listener ended because its link to the
// relay failed: no peer used the token, the daemon did not stop it, and
// it had not expired.
func (t *tokenTracker) linkLost() bool {
	return !t.consumed.Load() && !t.stopping.Load() &&
		time.Until(t.expiresAt) > relayExpirySlack
}

// Close closes the listener, and its connection if a peer used it.
func (t *tokenTracker) Close() error {
	t.stopping.Store(true)
	t.cancelExpiry()
	return t.Listener.Close()
}

func (t *tokenTracker) Stop() {
	t.stopping.Store(true)
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

// stampRelaySession records sessionID on the tracker that accepted the
// session's connection, if any. The caller holds the daemon lock.
func stampRelaySession(meta any, sessionID string) {
	if tt, ok := meta.(*tokenTracker); ok && tt != nil {
		tt.sessionID = sessionID
	}
}

// relayResumable reports whether the session sessionID may still be
// resumed: it has resumption tokens left. Closing a session, on either
// side, deletes them.
func relayResumable(store *storage.Storage, sessionID string) bool {
	if store == nil {
		return false
	}
	m, err := store.GetMeta(sessionID, storage.ResumptionTokensKey)
	return err == nil && len(decodeTokenList(m.Value())) > 0
}

// loadRelayPool returns the relay reconnect tokens stored for sessionID.
func loadRelayPool(store *storage.Storage, sessionID string) [][]byte {
	if sessionID == "" || store == nil {
		return nil
	}
	m, err := store.GetMeta(sessionID, storage.RelayTokensKey)
	if err != nil || m.Value() == nil {
		return nil
	}
	return decodeTokenList(m.Value())
}

func (t *tokenTracker) cancelExpiry() {
	t.expiryMu.Lock()
	defer t.expiryMu.Unlock()
	if t.expiry != nil {
		t.expiry.Stop()
	}
}

// startExpiryTimer stops t once its token expires and removes the token
// from the daemon's token list.
func startExpiryTimer(t *tokenTracker) {
	if t.ttl <= 0 {
		return
	}
	t.expiryMu.Lock()
	defer t.expiryMu.Unlock()
	t.expiry = time.AfterFunc(t.ttl, func() {
		t.Stop()
		t.app.relayTokenExpired(t)
	})
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

// defaultRelayScheme is the scheme of a relay address that names none.
// It is TLS: the relay handshake does not authenticate the relay, so
// over plain ws or tcp an on-path attacker can pose as the relay and
// read the relay password and tokens.
const defaultRelayScheme = "wss"

// parseRelayAddr splits a relay address into its scheme, tcp, ws, wss
// or tls, defaultRelayScheme when it names none, and its host. A
// trailing ?insecure=true or ?insecure=false overrides whether the TLS
// certificate is verified.
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
	return defaultRelayScheme, host, insecureOverride
}

// relayAddrWarning returns a warning about relayAddr when its connection
// does not authenticate the relay, or an empty string. Over plain ws or
// tcp, or TLS whose certificate is not verified, an on-path attacker can
// pose as the relay, read the relay password and the tokens, and join
// or take over relay sessions.
func relayAddrWarning(relayAddr string) string {
	scheme, host, insecure := parseRelayAddr(relayAddr)
	switch {
	case scheme == "ws" || scheme == "tcp":
		return "relay " + host + " is reached over " + scheme +
			" without TLS: an on-path attacker can read the relay " +
			"password and tokens; use wss:// or tls://"
	case insecure != nil && *insecure:
		return "relay " + host + " is reached without verifying its " +
			"TLS certificate: an on-path attacker can read the relay " +
			"password and tokens"
	}
	return ""
}

// warnRelayAddr logs the warning of relayAddrWarning, if any.
func (d *Daemon) warnRelayAddr(relayAddr string) {
	if w := relayAddrWarning(relayAddr); w != "" {
		d.addLogEntry("WARN", w)
	}
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
		wrapped := wrapRelayError(scheme, host, password != "", err)
		if registerSent(err) {
			wrapped = &tokenSentError{err: wrapped}
		}
		return nil, "", 0, 0, wrapped
	}
	return result.Listener, hex.EncodeToString(result.Token), result.TTL, result.SessionTTL, nil
}

// tokenSentError is the error of a relay registration that failed after
// it had sent its token to the relay.
type tokenSentError struct{ err error }

func (e *tokenSentError) Error() string { return e.err.Error() }
func (e *tokenSentError) Unwrap() error { return e.err }

// relayTokenSent reports whether err, from listenRelay, is that of a
// registration that sent its token to the relay before it failed.
func relayTokenSent(err error) bool {
	var sent *tokenSentError
	return errors.As(err, &sent)
}

// relayDialSteps begin the errors of the relayconn Listen helpers that
// could not connect to the relay.
var relayDialSteps = []string{
	"relay ws dial:", "relay wss dial:", "tcp dial:", "tls dial:",
}

// registerSent reports whether err, from a relayconn Listen helper,
// came after the helper sent the relay its Register frame, which holds
// the token. relayconn has no typed error for that, so it goes by the
// step that its error names: connecting, the HPKE exchange and the
// password come before the Register frame, and the steps after it name
// the frame, or are a wrong token in the relay's answer.
func registerSent(err error) bool {
	if errors.Is(err, relayconn.ErrRelayTokenMismatch) ||
		errors.Is(err, relayconn.ErrInvalidRelayToken) {
		return true
	}
	msg := err.Error()
	for _, step := range relayDialSteps {
		if strings.HasPrefix(msg, step) {
			return false
		}
	}
	return strings.Contains(msg, "register")
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
