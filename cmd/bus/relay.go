package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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
	// sessionID is the session that ran on the token's connection. It is
	// written and read under app.mu.
	sessionID string
	// resumeOf is the session that the token was registered for, so that
	// its peer can resume it, or empty. Only that session may run on the
	// listener; see admitsSession. It is set before the listener is in use
	// and not changed after.
	resumeOf string
	consumed atomic.Bool
	// peers holds the key of the peer a static token was derived for.
	peers peerKeySet
}

type trackingConn struct {
	kamune.Conn
	tracker *tokenTracker
	onClose func()
	once    sync.Once
}

func (c *trackingConn) AcceptedMeta() any { return c.tracker }

// admitsPeer reports whether a session through this token may be with
// the peer whose key is key; see peerGate.
func (t *tokenTracker) admitsPeer(key []byte) bool {
	return t.peers.admitsPeer(key)
}

// pinRelayListener ties a relay listener opened with a static token to
// the key of the peer the token was derived for.
func pinRelayListener(l kamune.Listener, peerKey []byte) {
	if tt, ok := l.(*tokenTracker); ok && peerKey != nil {
		tt.peers.allow(peerKey)
	}
}

func (c *trackingConn) Close() error {
	defer c.once.Do(c.onClose)
	return c.Conn.Close()
}

func (t *tokenTracker) Accept() (kamune.Conn, error) {
	cn, err := t.Listener.Accept()
	if err == nil {
		t.cancelExpiry()
		t.consumed.Store(true)
		t.app.markRelayTokenConsumed(t.token)
		return &trackingConn{
			Conn: cn, tracker: t, onClose: t.closeDead,
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

// ErrNotResumed is returned by the server handler for a session that came
// in through a relay listener registered for another session's peer to
// resume it on: only a resumption of that session may run on it.
var ErrNotResumed = errors.New(
	"the relay reconnect token is for resuming another session",
)

// admitsSession reports whether the session sessionID may run on the
// listener that its conn came in through, meta. A resume listener admits
// only the session it was registered for, which only that session's peer
// can resume, so a fresh handshake by whoever else learned the token, such
// as the relay operator, is turned away. Any other listener admits every
// session.
func admitsSession(meta any, sessionID string) bool {
	tt, ok := meta.(*tokenTracker)
	return !ok || tt == nil || tt.resumeOf == "" ||
		tt.resumeOf == sessionID
}

// stampRelaySession records sessionID on the tracker that accepted the
// session's connection, if any. The caller holds a.mu.
func stampRelaySession(meta any, sessionID string) {
	if tt, ok := meta.(*tokenTracker); ok && tt != nil {
		tt.sessionID = sessionID
	}
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

func dialRelayFunc(
	ctx context.Context, relayAddr, tokenHex, password string,
	insecureSkipVerify bool,
) (func(string) (kamune.Conn, error), error) {
	return dialRelayFuncWithSessionTTL(
		ctx, relayAddr, tokenHex, password, insecureSkipVerify, nil,
	)
}

// dialRelayFuncMultiToken returns a dial function that tries each of the given
// relay tokens in order, returning the first successful connection. The
// relay address is parsed once; only the token changes per attempt.
func dialRelayFuncMultiToken(
	ctx context.Context,
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

	if ctx == nil {
		ctx = context.Background()
	}
	scheme, host, insecureOverride := parseRelayAddr(relayAddr)
	if insecureOverride != nil {
		insecureSkipVerify = *insecureOverride
	}

	return func(addr string) (kamune.Conn, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
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

func dialRelayFuncWithSessionTTL(
	ctx context.Context, relayAddr, tokenHex, password string,
	insecureSkipVerify bool, sessionTTL *time.Duration,
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

	if ctx == nil {
		ctx = context.Background()
	}
	scheme, host, insecureOverride := parseRelayAddr(relayAddr)
	if insecureOverride != nil {
		insecureSkipVerify = *insecureOverride
	}

	return func(addr string) (kamune.Conn, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
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

// relayTarget is a running relay server's relay and the multiListener
// that its relay listeners join.
type relayTarget struct {
	addr      string
	password  string
	listeners *multiListener
}

// currentRelayTarget returns the running relay server's target, and false
// when no relay server runs.
func (a *App) currentRelayTarget() (relayTarget, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.relayListeners == nil {
		return relayTarget{}, false
	}
	return relayTarget{
		addr:      a.relayAddr,
		password:  a.relayPassword,
		listeners: a.relayListeners,
	}, true
}

// errServerStopped is returned by addRelayToken when the server that the
// new listener was to join stopped while it registered.
var errServerStopped = errors.New(
	"the server stopped while registering the token",
)

// addRelayToken registers a token with target's relay, staticToken or
// one the relay assigns when it is nil, adds its listener to target's
// server and lists it. tmpl gives the listed token's mode and peer.
// resumeOf names the session that the token is registered for, so that
// its peer can resume it, or is empty. It returns errServerStopped when
// the server stopped meanwhile.
func (a *App) addRelayToken(
	ctx context.Context,
	target relayTarget,
	staticToken []byte,
	tmpl relayToken,
	resumeOf string,
) (relayToken, error) {
	listener, token, ttl, sessionTTL, err := listenRelayTracked(
		ctx, a, target.addr, target.password, false, staticToken,
	)
	if err != nil {
		return relayToken{}, err
	}
	if tt, ok := listener.(*tokenTracker); ok {
		// Set before the listener is in use.
		tt.resumeOf = resumeOf
	}
	pinRelayListener(listener, staticPeerKey(tmpl.PeerPubB64, staticToken))

	rt := tmpl
	rt.Token = token
	rt.TTL = ttl
	rt.SessionTTL = sessionTTL
	rt.ExpiresAt = time.Now().Add(ttl)
	rt.listener = listener

	a.mu.Lock()
	if a.relayListeners != target.listeners ||
		target.listeners.Add(listener) != nil {
		a.mu.Unlock()
		_ = listener.Close()
		return relayToken{}, errServerStopped
	}
	a.relayTokens = append(a.relayTokens, rt)
	tokens := a.relayTokensSnapshotLocked()
	a.mu.Unlock()

	a.emitEvent("relay-tokens", tokens)
	return rt, nil
}

// resumeRelaySession starts keeping a relay listener registered for
// session, a server session that came in through the relay listener meta
// and whose connection dropped, so that its peer can resume it; see
// awaitRelayResume. It does nothing for a session that did not come
// through the relay or that cannot be resumed.
func (a *App) resumeRelaySession(meta any, session *liveSession) {
	if _, ok := meta.(*tokenTracker); !ok || a.sessionIncognito(session) {
		return
	}
	target, ok := a.currentRelayTarget()
	if !ok || a.lifeCtx().Err() != nil {
		return
	}
	go a.awaitRelayResume(target, session.ID)
}

// awaitRelayResume keeps a relay listener registered with one of the
// reconnect tokens of sessionID, a relay session of target's server whose
// connection dropped, so that its peer can resume the session through the
// relay. When the listener ends before a session has run on it, it
// registers another one after a short wait. It returns once a session has
// run on such a listener, when the server stops, or when no reconnect
// token is stored for the session or the relay takes none.
func (a *App) awaitRelayResume(target relayTarget, sessionID string) {
	const (
		minBackoff = 1 * time.Second
		maxBackoff = 5 * time.Second
	)
	// Registering stops with the server, or when the app shuts down.
	ctx, cancel := context.WithCancel(a.lifeCtx())
	defer cancel()
	go func() {
		select {
		case <-target.listeners.Done():
			cancel()
		case <-ctx.Done():
		}
	}()

	for {
		tokens := loadRelayPool(a.store(), sessionID)
		if len(tokens) == 0 {
			a.addLogEntry("INFO",
				"No relay reconnect tokens for session "+sessionID+
					"; it cannot resume through the relay")
			return
		}

		var tt *tokenTracker
		for _, token := range tokens {
			rt, err := a.addRelayToken(
				ctx, target, token, relayToken{Mode: "ecdh"}, sessionID,
			)
			if errors.Is(err, errServerStopped) || ctx.Err() != nil {
				return
			}
			if err != nil {
				a.addLogEntry("WARN",
					"Relay reconnect registration failed: "+err.Error())
				continue
			}
			tt, _ = rt.listener.(*tokenTracker)
			a.addLogEntry("INFO",
				"Relay reconnect listener registered for session "+
					sessionID)
			break
		}
		if tt == nil {
			a.addLogEntry("WARN",
				"The relay took no reconnect token for session "+
					sessionID+"; it cannot resume through the relay")
			return
		}

		select {
		case <-tt.Dead():
		case <-ctx.Done():
			return
		}
		a.mu.RLock()
		resumed := tt.sessionID != ""
		a.mu.RUnlock()
		if resumed {
			return
		}

		jitter := time.Duration(rand.Int63n(int64(maxBackoff - minBackoff)))
		select {
		case <-time.After(minBackoff + jitter):
		case <-ctx.Done():
			return
		}
	}
}
