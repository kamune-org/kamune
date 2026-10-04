package relayconn

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"

	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/relayconn/pb"
)

// DialRelay joins the relay session named by token over a WebSocket
// (ws://relayAddr/ws) and returns the connection to the listening peer.
// ctx and the handshake timeout bound connecting and the relay handshake
// only: cancelling ctx after DialRelay returns does not affect the
// connection, which lasts until Close.
func DialRelay(
	ctx context.Context, relayAddr string, token []byte, opts ...Option,
) (*RelayConn, error) {
	dctx, cancel, opts := startHandshake(ctx, opts)
	defer cancel()
	ws, err := dialWS(dctx, fmt.Sprintf("ws://%s/ws", relayAddr), nil)
	if err != nil {
		return nil, fmt.Errorf("relay ws dial: %w", err)
	}
	adapter := newWSAdapter(ctx, ws)
	return relayHandshake(
		ctx,
		adapter,
		token,
		adapter.abort,
		opts...,
	)
}

// DialRelayWSS is DialRelay over a WebSocket on TLS
// (wss://relayAddr/ws) configured by tlsCfg.
func DialRelayWSS(
	ctx context.Context,
	relayAddr string,
	token []byte,
	tlsCfg *tls.Config,
	opts ...Option,
) (*RelayConn, error) {
	dopts := &websocket.DialOptions{
		HTTPClient: &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
	}
	dctx, cancel, opts := startHandshake(ctx, opts)
	defer cancel()
	ws, err := dialWS(dctx, fmt.Sprintf("wss://%s/ws", relayAddr), dopts)
	if err != nil {
		return nil, fmt.Errorf("relay wss dial: %w", err)
	}
	adapter := newWSAdapter(ctx, ws)
	return relayHandshake(
		ctx,
		adapter,
		token,
		adapter.abort,
		opts...,
	)
}

// DialRelayTCP is DialRelay over raw TCP with the relay's
// length-prefixed framing.
func DialRelayTCP(
	ctx context.Context, relayAddr string, token []byte, opts ...Option,
) (*RelayConn, error) {
	dctx, cancel, opts := startHandshake(ctx, opts)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(dctx, "tcp", relayAddr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial: %w", err)
	}
	adapter := newTCPAdapter(conn)
	return relayHandshake(ctx, adapter, token, func() { conn.Close() }, opts...)
}

// DialRelayTLS is DialRelayTCP over TLS configured by tlsCfg.
func DialRelayTLS(
	ctx context.Context,
	relayAddr string,
	token []byte,
	tlsCfg *tls.Config,
	opts ...Option,
) (*RelayConn, error) {
	dctx, cancel, opts := startHandshake(ctx, opts)
	defer cancel()
	conn, err := dialTLS(dctx, relayAddr, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("tls dial: %w", err)
	}
	adapter := newTLSAdapter(conn)
	return relayHandshake(ctx, adapter, token, func() { conn.Close() }, opts...)
}

// relayHandshake performs the dialer side of the relay protocol:
// HPKE key exchange, optional PSK auth, registration with token,
// and starting the readPump goroutine. When ctx ends or the handshake
// deadline in opts passes first, closeFn closes the socket so that a
// relay that stops answering cannot block the handshake.
func relayHandshake(
	ctx context.Context,
	rw exchange.ReadWriter,
	token []byte,
	closeFn func(),
	opts ...Option,
) (_ *RelayConn, retErr error) {
	o := buildOptions(opts)
	hctx, cancel := o.handshakeContext(ctx)
	defer cancel()
	stop := context.AfterFunc(hctx, closeFn)
	defer stop()
	defer func() { retErr = handshakeErr(hctx, retErr) }()

	ch, err := exchange.Initiate(rw)
	if err != nil {
		closeFn()
		return nil, fmt.Errorf("hpke initiate: %w", err)
	}
	defer func() {
		if retErr != nil {
			ch.Close()
		}
	}()

	if o.password != "" {
		if err := sendAuth(ch, o.password); err != nil {
			return nil, err
		}
	}

	registerFrame := &pb.Frame{
		Kind: &pb.Frame_Register{Register: &pb.Register{
			Mode:  pb.Register_MODE_JOIN,
			Token: token,
		}},
	}
	regBytes, err := proto.Marshal(registerFrame)
	if err != nil {
		return nil, fmt.Errorf("marshal register: %w", err)
	}
	if err := ch.WriteBytes(regBytes); err != nil {
		return nil, fmt.Errorf("send register: %w", err)
	}

	relayBytes, err := ch.ReadBytes()
	if err != nil {
		return nil, fmt.Errorf("read registered: %w", err)
	}
	var relayFrame pb.Frame
	if err := proto.Unmarshal(relayBytes, &relayFrame); err != nil {
		return nil, fmt.Errorf("unmarshal registered: %w", err)
	}
	reg := relayFrame.GetRegistered()
	if reg == nil {
		return nil, fmt.Errorf(
			"unexpected frame: expected registered, got %T", relayFrame.Kind,
		)
	}
	if err := checkRegisteredToken(reg.GetToken(), token); err != nil {
		return nil, err
	}

	if !stop() {
		return nil, errors.New("handshake ended while registering")
	}

	// ctx bounds only the handshake; the connection lasts until Close.
	var mu sync.Mutex
	rc := newRelayConn(context.WithoutCancel(ctx), ch, &mu)
	rc.ttl = time.Duration(reg.GetTtlSeconds()) * time.Second
	rc.sessionTTL = time.Duration(reg.GetSessionTtlSeconds()) * time.Second
	rc.closeFn = func() { ch.Close() }

	go rc.readPump()
	return rc, nil
}

// dialTLS connects to addr over TLS. Both the TCP connect and the TLS
// handshake end when ctx does.
func dialTLS(
	ctx context.Context, addr string, cfg *tls.Config,
) (*tls.Conn, error) {
	d := tls.Dialer{Config: cfg}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return conn.(*tls.Conn), nil
}

// handshakeErr reports why a relay handshake failed. When its context
// ended, closing the socket is what broke the handshake, so the
// context's error is returned with the I/O error.
func handshakeErr(hctx context.Context, err error) error {
	if err == nil || hctx.Err() == nil {
		return err
	}
	return fmt.Errorf("relay handshake: %w: %w", context.Cause(hctx), err)
}
