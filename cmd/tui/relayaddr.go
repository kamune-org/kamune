package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/kamune-org/kamune/pkg/relayconn"
)

// defaultRelayScheme is the scheme of a relay address that names none.
// wss checks the relay's certificate, and on the wire it looks like any
// other HTTPS connection.
const defaultRelayScheme = "wss"

// errRelayAddress is returned for a relay address that cannot be used.
var errRelayAddress = errors.New("invalid relay address")

// relayTarget is a relay and the way to reach it, as a relay address
// names them: scheme://host:port, where scheme is wss, tls, ws or tcp.
type relayTarget struct {
	scheme string
	// host is host:port, or for ws and wss also a bare host, which
	// stands for the scheme's default port.
	host string
}

// parseRelayAddr parses a relay address. An address without a scheme
// uses defaultRelayScheme.
func parseRelayAddr(addr string) (relayTarget, error) {
	addr = strings.TrimSpace(addr)
	scheme, host, found := strings.Cut(addr, "://")
	if !found {
		scheme, host = defaultRelayScheme, addr
	}
	scheme = strings.ToLower(scheme)
	switch scheme {
	case "wss", "tls", "ws", "tcp":
	default:
		return relayTarget{}, fmt.Errorf(
			"%w: unknown scheme %q; use wss, tls, ws or tcp",
			errRelayAddress, scheme,
		)
	}
	if host == "" || strings.ContainsAny(host, "/?#@ \t") {
		return relayTarget{}, fmt.Errorf(
			"%w: %q is not host:port", errRelayAddress, host,
		)
	}
	_, _, err := net.SplitHostPort(host)
	if err != nil && (scheme == "tls" || scheme == "tcp") {
		return relayTarget{}, fmt.Errorf(
			"%w: %s needs host:port", errRelayAddress, scheme,
		)
	}
	return relayTarget{scheme: scheme, host: host}, nil
}

// secure reports whether r reaches the relay over TLS, which tells the
// relay from an impostor. Over ws and tcp, anyone on the path can pose
// as the relay and read the session token.
func (r relayTarget) secure() bool {
	return r.scheme == "wss" || r.scheme == "tls"
}

// tlsConfig returns the TLS config for a wss or tls relay. It checks the
// relay's certificate against the system's roots and the relay's name.
func (r relayTarget) tlsConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12}
}

// dial joins the relay session named by token.
func (r relayTarget) dial(
	ctx context.Context, token []byte, opts ...relayconn.Option,
) (*relayconn.RelayConn, error) {
	switch r.scheme {
	case "wss":
		return relayconn.DialRelayWSS(
			ctx, r.host, token, r.tlsConfig(), opts...,
		)
	case "tls":
		return relayconn.DialRelayTLS(
			ctx, r.host, token, r.tlsConfig(), opts...,
		)
	case "ws":
		return relayconn.DialRelay(ctx, r.host, token, opts...)
	case "tcp":
		return relayconn.DialRelayTCP(ctx, r.host, token, opts...)
	}
	return nil, fmt.Errorf("%w: unknown scheme %q", errRelayAddress, r.scheme)
}

// listen registers a new relay session.
func (r relayTarget) listen(
	ctx context.Context, opts ...relayconn.Option,
) (*relayconn.ListenResult, error) {
	switch r.scheme {
	case "wss":
		return relayconn.ListenRelayWSS(ctx, r.host, r.tlsConfig(), opts...)
	case "tls":
		return relayconn.ListenRelayTLS(ctx, r.host, r.tlsConfig(), opts...)
	case "ws":
		return relayconn.ListenRelay(ctx, r.host, opts...)
	case "tcp":
		return relayconn.ListenRelayTCP(ctx, r.host, opts...)
	}
	return nil, fmt.Errorf("%w: unknown scheme %q", errRelayAddress, r.scheme)
}
