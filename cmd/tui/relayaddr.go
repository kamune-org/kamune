package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
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
	// pin, when set, is the SHA-256 fingerprint of the certificate that
	// a wss or tls relay must have. It takes the place of the checks
	// against the system's roots and the relay's name.
	pin []byte
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

// pinned returns r with the certificate fingerprint fp, as
// relayconn.ParseCertFingerprint reads it, or r itself if fp is empty.
// Only a wss or tls relay has a certificate to pin.
func (r relayTarget) pinned(fp string) (relayTarget, error) {
	if strings.TrimSpace(fp) == "" {
		return r, nil
	}
	if !r.secure() {
		return relayTarget{}, fmt.Errorf(
			"%w: a certificate fingerprint needs a wss or tls relay",
			errRelayAddress,
		)
	}
	pin, err := relayconn.ParseCertFingerprint(fp)
	if err != nil {
		return relayTarget{}, err
	}
	r.pin = pin
	return r, nil
}

// secure reports whether r reaches the relay over TLS, which tells the
// relay from an impostor. Over ws and tcp, anyone on the path can pose
// as the relay and read the session token.
func (r relayTarget) secure() bool {
	return r.scheme == "wss" || r.scheme == "tls"
}

// tlsConfig returns the TLS config for a wss or tls relay. It accepts
// only the certificate with the pinned fingerprint, if r has one, and
// otherwise checks the relay's certificate against the system's roots
// and the relay's name.
func (r relayTarget) tlsConfig() (*tls.Config, error) {
	if r.pin != nil {
		return relayconn.PinnedTLSConfig(r.pin)
	}
	return &tls.Config{MinVersion: tls.VersionTLS12}, nil
}

// dial joins the relay session named by token.
func (r relayTarget) dial(
	ctx context.Context, token []byte, opts ...relayconn.Option,
) (*relayconn.RelayConn, error) {
	cfg, err := r.tlsConfig()
	if err != nil {
		return nil, err
	}
	var conn *relayconn.RelayConn
	switch r.scheme {
	case "wss":
		conn, err = relayconn.DialRelayWSS(ctx, r.host, token, cfg, opts...)
	case "tls":
		conn, err = relayconn.DialRelayTLS(ctx, r.host, token, cfg, opts...)
	case "ws":
		conn, err = relayconn.DialRelay(ctx, r.host, token, opts...)
	case "tcp":
		conn, err = relayconn.DialRelayTCP(ctx, r.host, token, opts...)
	default:
		err = fmt.Errorf("%w: unknown scheme %q", errRelayAddress, r.scheme)
	}
	return conn, untrusted(err)
}

// listen registers a new relay session.
func (r relayTarget) listen(
	ctx context.Context, opts ...relayconn.Option,
) (*relayconn.ListenResult, error) {
	cfg, err := r.tlsConfig()
	if err != nil {
		return nil, err
	}
	var res *relayconn.ListenResult
	switch r.scheme {
	case "wss":
		res, err = relayconn.ListenRelayWSS(ctx, r.host, cfg, opts...)
	case "tls":
		res, err = relayconn.ListenRelayTLS(ctx, r.host, cfg, opts...)
	case "ws":
		res, err = relayconn.ListenRelay(ctx, r.host, opts...)
	case "tcp":
		res, err = relayconn.ListenRelayTCP(ctx, r.host, opts...)
	default:
		err = fmt.Errorf("%w: unknown scheme %q", errRelayAddress, r.scheme)
	}
	return res, untrusted(err)
}

// untrusted adds a hint to err when the relay's certificate did not pass
// the checks against the system's roots, as a self-signed one does not.
func untrusted(err error) error {
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		return fmt.Errorf("%w (to trust a relay with a self-signed "+
			"certificate, enter the SHA-256 fingerprint that it logs "+
			"at startup)", err)
	}
	return err
}

// hungUp adds a hint to err, the error of a relay handshake, when the
// relay hung up in the middle of it. A relay hangs up on a client that
// gives a wrong password, none when the relay has one, or one when it
// has none, and on a dialer whose token it does not know. check names
// what the user should check.
func hungUp(err error, check string) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("%w (the relay hung up; check %s)", err, check)
	}
	return err
}
