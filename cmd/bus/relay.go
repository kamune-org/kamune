package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/relayconn"
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
	expiresAt  time.Time
	app        *App
	expiryOnce sync.Once
	expiryFn   func()
}

func (t *tokenTracker) Accept() (kamune.Conn, error) {
	cn, err := t.Listener.Accept()
	if err == nil {
		t.cancelExpiry()
		t.app.markRelayTokenConsumed(t.token)
	}
	return cn, err
}

func (t *tokenTracker) Stop() {
	t.cancelExpiry()
	if s, ok := t.Listener.(interface{ Stop() }); ok {
		s.Stop()
	}
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

func listenRelayTracked(ctx context.Context, a *App, relayAddr, password string, insecureSkipVerify bool) (kamune.Listener, string, time.Duration, error) {
	listener, tokenHex, ttl, err := listenRelay(ctx, relayAddr, password, insecureSkipVerify)
	if err != nil {
		return nil, "", 0, err
	}
	tracker := &tokenTracker{
		Listener:  listener,
		token:     tokenHex,
		ttl:       ttl,
		expiresAt: time.Now().Add(ttl),
		app:       a,
	}
	startExpiryTimer(tracker)
	return tracker, tokenHex, ttl, nil
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

func listenRelay(ctx context.Context, relayAddr, password string, insecureSkipVerify bool) (kamune.Listener, string, time.Duration, error) {
	if strings.TrimSpace(relayAddr) == "" {
		return nil, "", 0, errors.New("relay server address is required")
	}

	var opts []relayconn.Option
	if password != "" {
		opts = append(opts, relayconn.WithPassword(password))
	}

	scheme, host, insecureOverride := parseRelayAddr(relayAddr)
	if insecureOverride != nil {
		insecureSkipVerify = *insecureOverride
	}

	var (
		listener *relayconn.RelayListener
		token    []byte
		ttl      time.Duration
		err      error
	)
	switch scheme {
	case "tcp":
		listener, token, ttl, err = relayconn.ListenRelayTCP(ctx, host, opts...)
	case "wss":
		listener, token, ttl, err = relayconn.ListenRelayWSS(ctx, host, &tls.Config{InsecureSkipVerify: insecureSkipVerify}, opts...)
	case "tls":
		listener, token, ttl, err = relayconn.ListenRelayTLS(ctx, host, &tls.Config{InsecureSkipVerify: insecureSkipVerify}, opts...)
	default:
		listener, token, ttl, err = relayconn.ListenRelay(ctx, host, opts...)
	}
	if err != nil {
		return nil, "", 0, wrapRelayError(scheme, host, password != "", err)
	}
	return listener, hex.EncodeToString(token), ttl, nil
}

func dialRelayFunc(relayAddr, tokenHex, password string, insecureSkipVerify bool) (func(string) (kamune.Conn, error), error) {
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
		return conn, nil
	}, nil
}
