package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/relayconn"
	"github.com/kamune-org/kamune/pkg/storage"
)

// wrapRelayError names the relay at scheme://host in err, which dialing
// it or registering with it returned, and adds a hint at a likely cause:
// a wrong password or token when the relay closed the connection, and a
// missing certificate pin when no trusted authority signed the relay's
// certificate, as for the self-signed one a relay makes for itself.
func wrapRelayError(scheme, host string, password bool, err error) error {
	var hint string
	var unknown x509.UnknownAuthorityError
	switch {
	case strings.Contains(err.Error(), "received close frame"):
		hint = "; relay closed the connection"
		if password {
			hint += " — wrong password?"
		} else {
			hint += " — try providing a password or check the token"
		}
	case errors.As(err, &unknown):
		hint = "; no trusted authority vouches for the relay's " +
			"certificate — enter its SHA-256 fingerprint as the relay " +
			"certificate pin"
	}
	return fmt.Errorf("%s://%s%s: %w", scheme, host, hint, err)
}

// logToken names the relay or broker token tok in the log by its first
// eight hex characters: whoever reads a full token in the log could use
// it.
func logToken(tok string) string {
	if len(tok) <= 8 {
		return tok
	}
	return tok[:8] + "…"
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
	// removed is set once the user removes the token from the list; see
	// App.RemoveRelayToken.
	removed atomic.Bool
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

// relayResumable reports whether the session sessionID may still be
// resumed: it has resumption tokens left. Closing a session, on either
// side, deletes them.
func relayResumable(store *storage.Storage, sessionID string) bool {
	if store == nil || sessionID == "" {
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
		t.app.addLogEntry("INFO", "Relay token expired: "+logToken(t.token))
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

// ErrRelayPinScheme rejects a relay address with a certificate pin whose
// scheme does not use TLS, where there is no certificate to pin.
var ErrRelayPinScheme = errors.New(
	"a relay certificate pin needs a wss:// or tls:// relay address",
)

// relayAddress is a relay address as the user gives it:
//
//	[scheme://]host:port[?insecure=true|false][&pin=<sha256>]
//
// An address without a scheme is taken as wss, so that the relay's
// certificate is checked unless asked otherwise.
type relayAddress struct {
	scheme string
	host   string
	// insecure is the ?insecure= override of the caller's choice to skip
	// TLS verification, or nil.
	insecure *bool
	// pin is the SHA-256 fingerprint of the relay's certificate from
	// ?pin=, or nil. The relay logs it at startup; see
	// relayconn.ParseCertFingerprint for the forms it may take.
	pin []byte
}

// parseRelayAddr parses a relay address; see relayAddress. A query with
// a key other than insecure and pin, or a bad value for one of them, is
// an error, and so is a pin on a scheme other than wss and tls.
func parseRelayAddr(addr string) (relayAddress, error) {
	addr = strings.TrimSpace(addr)
	ra := relayAddress{scheme: "wss"}
	for _, s := range []string{"tcp://", "ws://", "wss://", "tls://"} {
		if strings.HasPrefix(addr, s) {
			ra.scheme = strings.TrimSuffix(s, "://")
			addr = addr[len(s):]
			break
		}
	}
	host, query, hasQuery := strings.Cut(addr, "?")
	ra.host = host
	if !hasQuery {
		return ra, nil
	}
	values, err := url.ParseQuery(query)
	if err != nil {
		return relayAddress{}, fmt.Errorf("relay address query: %w", err)
	}
	for key, vals := range values {
		if len(vals) != 1 {
			return relayAddress{}, fmt.Errorf(
				"relay address: %s is given %d times", key, len(vals),
			)
		}
		switch val := vals[0]; key {
		case "insecure":
			switch val {
			case "true", "false":
				v := val == "true"
				ra.insecure = &v
			default:
				return relayAddress{}, fmt.Errorf(
					"relay address: insecure must be true or false, not %q",
					val,
				)
			}
		case "pin":
			pin, err := relayconn.ParseCertFingerprint(val)
			if err != nil {
				return relayAddress{}, fmt.Errorf("relay address: %w", err)
			}
			ra.pin = pin
		default:
			return relayAddress{}, fmt.Errorf(
				"relay address: unknown parameter %q", key,
			)
		}
	}
	if ra.pin != nil && ra.scheme != "wss" && ra.scheme != "tls" {
		return relayAddress{}, ErrRelayPinScheme
	}
	return ra, nil
}

// tlsConfig returns the TLS config for a wss or tls relay at ra. With a
// pin, it trusts exactly the pinned certificate, whatever
// insecureSkipVerify says. Without one, it checks the certificate chain
// and host name unless verification is skipped, by insecureSkipVerify or
// the address's ?insecure= override; that lets anyone on the path pose
// as the relay and read the relay password and token.
func (ra relayAddress) tlsConfig(
	insecureSkipVerify bool,
) (*tls.Config, error) {
	if ra.pin != nil {
		return relayconn.PinnedTLSConfig(ra.pin)
	}
	if ra.insecure != nil {
		insecureSkipVerify = *ra.insecure
	}
	return &tls.Config{
		InsecureSkipVerify: insecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
	}, nil
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

	ra, err := parseRelayAddr(relayAddr)
	if err != nil {
		return nil, "", 0, 0, err
	}
	scheme, host := ra.scheme, ra.host
	tlsCfg, err := ra.tlsConfig(insecureSkipVerify)
	if err != nil {
		return nil, "", 0, 0, err
	}

	var result *relayconn.ListenResult
	switch scheme {
	case "tcp":
		result, err = relayconn.ListenRelayTCP(ctx, host, opts...)
	case "wss":
		result, err = relayconn.ListenRelayWSS(ctx, host, tlsCfg, opts...)
	case "tls":
		result, err = relayconn.ListenRelayTLS(ctx, host, tlsCfg, opts...)
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
	ra, err := parseRelayAddr(relayAddr)
	if err != nil {
		return nil, err
	}
	scheme, host := ra.scheme, ra.host
	tlsCfg, err := ra.tlsConfig(insecureSkipVerify)
	if err != nil {
		return nil, err
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
				conn, err = relayconn.DialRelayWSS(
					ctx, host, rawToken, tlsCfg, opts...,
				)
			case "tls":
				conn, err = relayconn.DialRelayTLS(
					ctx, host, rawToken, tlsCfg, opts...,
				)
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
	ra, err := parseRelayAddr(relayAddr)
	if err != nil {
		return nil, err
	}
	scheme, host := ra.scheme, ra.host
	tlsCfg, err := ra.tlsConfig(insecureSkipVerify)
	if err != nil {
		return nil, err
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
			conn, err = relayconn.DialRelayWSS(
				ctx, host, token, tlsCfg, opts...,
			)
		case "tls":
			conn, err = relayconn.DialRelayTLS(
				ctx, host, token, tlsCfg, opts...,
			)
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

// defaultRelayResumeWindow bounds how long after a relay session drops
// the server registers listeners for its peer to resume it on. A bus or
// daemon dialer gives up reconnecting well within it.
const defaultRelayResumeWindow = 10 * time.Minute

// resumeWindow returns how long after a relay session drops the server
// registers listeners for its peer to resume it on.
func (a *App) resumeWindow() time.Duration {
	if a.relayResumeWindow > 0 {
		return a.relayResumeWindow
	}
	return defaultRelayResumeWindow
}

// resumeRelaySession starts keeping a relay listener registered for
// session, a server session that came in through the relay listener meta
// and whose connection dropped, so that its peer can resume it; see
// awaitRelayResume. It reports false, and starts nothing, for a session
// that did not come through the relay or that cannot be resumed.
func (a *App) resumeRelaySession(meta any, session *liveSession) bool {
	if _, ok := meta.(*tokenTracker); !ok || session.incognito ||
		a.lifeCtx().Err() != nil {
		return false
	}
	// Counted under a.mu, so that StopServer, which takes the count
	// away under it, waits for every resume of its server.
	a.mu.RLock()
	resumes := a.relayResumes
	target := relayTarget{
		addr:      a.relayAddr,
		password:  a.relayPassword,
		listeners: a.relayListeners,
	}
	if resumes == nil || target.listeners == nil {
		a.mu.RUnlock()
		return false
	}
	resumes.Add(1)
	a.mu.RUnlock()
	go func() {
		defer resumes.Done()
		a.awaitRelayResume(target, session.ID)
	}()
	return true
}

// awaitRelayResume keeps a relay listener registered with one of the
// reconnect tokens of sessionID, a relay session of target's server whose
// connection dropped, so that its peer can resume the session through the
// relay. It registers one token at a time. A token that the relay
// registered a listener with is removed from the stored pool, so it is
// never registered twice; see registerResumeToken. When the listener ends
// before the session resumed on it, it registers the next token after a
// short wait. When the relay turns a registration away, as a full relay
// does, it registers the same token again after a wait that grows while
// registrations keep failing. It returns once the session resumed on
// such a listener, when the server stops, when the user removes the
// listener's token, when the session can no longer be resumed or has no
// reconnect token left, and once the resume window has passed. When the
// window ends it stops the live listener, so that the relay drops its
// token, and a session already on it carries on. Unless the session
// resumed or the app is shutting down, it then drops the session's
// remaining reconnect tokens.
func (a *App) awaitRelayResume(target relayTarget, sessionID string) {
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
	window, endWindow := context.WithTimeout(ctx, a.resumeWindow())
	defer endWindow()

	resumed := false
	defer func() {
		if !resumed && a.lifeCtx().Err() == nil {
			a.dropRelayPool(sessionID)
		}
	}()
	failures := 0
	for {
		store := a.store()
		if !relayResumable(store, sessionID) {
			a.addLogEntry("INFO",
				"Session "+sessionID+" can no longer be resumed; "+
					"its relay reconnect tokens are dropped")
			return
		}
		tokens := loadRelayPool(store, sessionID)
		if len(tokens) == 0 {
			a.addLogEntry("INFO",
				"No relay reconnect tokens left for session "+sessionID+
					"; it cannot resume through the relay")
			return
		}

		tt, err := a.registerResumeToken(ctx, target, sessionID, tokens[0])
		if errors.Is(err, errServerStopped) || ctx.Err() != nil {
			return
		}
		if err != nil {
			failures++
		} else {
			failures = 0
			var removed bool
			resumed, removed = a.watchResumeListener(ctx, window, tt)
			switch {
			case ctx.Err() != nil, resumed:
				return
			case removed:
				a.addLogEntry("INFO",
					"The relay reconnect token of session "+sessionID+
						" was removed; it cannot resume through the relay")
				return
			}
		}
		if window.Err() != nil ||
			!a.waitResume(window, resumeBackoff(failures)) {
			if ctx.Err() == nil {
				a.addLogEntry("INFO",
					"Session "+sessionID+" was not resumed through the "+
						"relay in time; its relay reconnect tokens are "+
						"dropped")
			}
			return
		}
	}
}

// resumeBackoff returns how long awaitRelayResume waits before it
// registers again: one to five seconds after a listener that ended
// unused, and after failures registrations in a row failed, one second
// doubling up to 30 seconds, as a bus dialer spaces its reconnect
// attempts.
func resumeBackoff(failures int) time.Duration {
	const (
		minWait = 1 * time.Second
		maxWait = 30 * time.Second
	)
	if failures <= 0 {
		jitter := rand.Int63n(int64(4 * time.Second))
		return minWait + time.Duration(jitter)
	}
	return min(minWait<<min(failures-1, 5), maxWait)
}

// waitResume waits d, or less when ctx ends first, and reports whether
// the whole wait passed. App.relayResumeWait replaces it when set.
func (a *App) waitResume(ctx context.Context, d time.Duration) bool {
	if a.relayResumeWait != nil {
		return a.relayResumeWait(ctx, d)
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// registerResumeToken registers a listener for sessionID with token and
// returns its tracker. Once the relay has registered a listener with the
// token, the token is removed from the stored pool, so that it is never
// registered twice. So is a token that the relay answers with another
// one, which shows that it will not take the token. A token that the
// relay turned away without registering it, as a full relay does by
// closing the connection, stays in the pool for the next attempt: the
// relay learns nothing new from a token it has already seen, and the
// dialer sends it on each of its reconnect attempts anyway. It returns
// errServerStopped when the server stopped meanwhile.
func (a *App) registerResumeToken(
	ctx context.Context,
	target relayTarget,
	sessionID string,
	token []byte,
) (*tokenTracker, error) {
	rt, err := a.addRelayToken(
		ctx, target, token, relayToken{Mode: "ecdh"}, sessionID,
	)
	if errors.Is(err, errServerStopped) {
		return nil, err
	}
	if err == nil || relayTokenRefused(err) {
		a.removePoolToken(sessionID, token)
	}
	if err != nil {
		a.addLogEntry("WARN",
			"Relay reconnect registration failed: "+err.Error())
		return nil, err
	}
	a.addLogEntry("INFO",
		"Relay reconnect listener registered for session "+sessionID)
	tt, _ := rt.listener.(*tokenTracker)
	return tt, nil
}

// watchResumeListener waits for tt, a resume listener's tracker, to end,
// and reports whether the session resumed on it and whether the user
// removed its token. When window ends first, it stops tt, which ends it
// unless a peer is already on it, and waits on. It reports neither when
// ctx ends first.
func (a *App) watchResumeListener(
	ctx, window context.Context, tt *tokenTracker,
) (resumed, removed bool) {
	select {
	case <-tt.Dead():
	case <-window.Done():
		if ctx.Err() != nil {
			return false, false
		}
		tt.Stop()
		select {
		case <-tt.Dead():
		case <-ctx.Done():
			return false, false
		}
	}
	return a.endResumeListener(tt)
}

// endResumeListener handles the end of tt, a resume listener's tracker.
// It reports whether the session resumed on it, and whether the user
// removed its token. A listed token that no session used is taken off the
// list. The list does not tell whether the user removed a token: one that
// a peer used leaves it a few seconds later in any case (see
// App.markRelayTokenConsumed), even when no session came of it.
func (a *App) endResumeListener(tt *tokenTracker) (resumed, removed bool) {
	a.mu.Lock()
	resumed = tt.sessionID != ""
	idx := slices.IndexFunc(a.relayTokens, func(rt relayToken) bool {
		return rt.listener == tt
	})
	unlist := idx >= 0 && !resumed
	if unlist {
		a.relayTokens = slices.Delete(a.relayTokens, idx, idx+1)
	}
	tokens := a.relayTokensSnapshotLocked()
	a.mu.Unlock()
	if unlist {
		a.emitEvent("relay-tokens", tokens)
	}
	return resumed, tt.removed.Load()
}

// removePoolToken removes token from the relay reconnect tokens stored
// for sessionID.
func (a *App) removePoolToken(sessionID string, token []byte) {
	store := a.store()
	if store == nil {
		return
	}
	err := store.RemoveListItem(sessionID, storage.RelayTokensKey, token)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		a.addLogEntry("WARN",
			"Failed to drop a used relay reconnect token: "+err.Error())
	}
}

// dropRelayPool deletes the relay reconnect tokens stored for sessionID,
// once the session is over and no peer may resume it.
func (a *App) dropRelayPool(sessionID string) {
	store := a.store()
	if store == nil {
		return
	}
	if err := store.DeleteMeta(sessionID, storage.RelayTokensKey); err != nil {
		a.addLogEntry("DEBUG",
			"Failed to drop relay reconnect tokens: "+err.Error())
	}
}

// relayTokenRefused reports whether err, from the registration of a
// listener with a token of our own, shows that the relay will not take
// that token: it answered with another token, or an invalid one. After
// any other failure, such as a relay that closes the connection because
// it is full, no listener holds the token, which may be registered
// again. It goes by relayconn's typed errors, not by error text.
func relayTokenRefused(err error) bool {
	return errors.Is(err, relayconn.ErrRelayTokenMismatch) ||
		errors.Is(err, relayconn.ErrInvalidRelayToken)
}
