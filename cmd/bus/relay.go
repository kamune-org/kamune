package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

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
	token string
	app   *App
}

func (t *tokenTracker) Accept() (kamune.Conn, error) {
	cn, err := t.Listener.Accept()
	if err == nil {
		t.app.markRelayTokenConsumed(t.token)
	}
	return cn, err
}

func listenRelayTracked(ctx context.Context, a *App, relayAddr, password string, insecureSkipVerify bool) (kamune.Listener, string, error) {
	listener, tokenHex, err := listenRelay(ctx, relayAddr, password, insecureSkipVerify)
	if err != nil {
		return nil, "", err
	}
	return &tokenTracker{Listener: listener, token: tokenHex, app: a}, tokenHex, nil
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

func listenRelay(ctx context.Context, relayAddr, password string, insecureSkipVerify bool) (kamune.Listener, string, error) {
	if strings.TrimSpace(relayAddr) == "" {
		return nil, "", errors.New("relay server address is required")
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
		err      error
	)
	switch scheme {
	case "tcp":
		listener, token, err = relayconn.ListenRelayTCP(ctx, host, opts...)
	case "wss":
		listener, token, err = relayconn.ListenRelayWSS(ctx, host, &tls.Config{InsecureSkipVerify: insecureSkipVerify}, opts...)
	case "tls":
		listener, token, err = relayconn.ListenRelayTLS(ctx, host, &tls.Config{InsecureSkipVerify: insecureSkipVerify}, opts...)
	default:
		listener, token, err = relayconn.ListenRelay(ctx, host, opts...)
	}
	if err != nil {
		return nil, "", wrapRelayError(scheme, host, password != "", err)
	}
	return listener, hex.EncodeToString(token), nil
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
