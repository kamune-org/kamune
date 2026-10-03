package relayconn

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/relayconn/pb"
)

type RelayListener struct {
	ctx        context.Context
	channel    *exchange.Channel
	accept     chan *RelayConn
	cancel     context.CancelFunc
	closeFn    func()
	conn       *RelayConn
	closeOnce  sync.Once
	channelMu  sync.Mutex
	mu         sync.Mutex
	stopped    atomic.Bool
	ttl        time.Duration
	sessionTTL time.Duration
}

type ListenResult struct {
	Listener   *RelayListener
	Token      []byte
	TTL        time.Duration
	SessionTTL time.Duration
}

func (l *RelayListener) TTL() time.Duration        { return l.ttl }
func (l *RelayListener) SessionTTL() time.Duration { return l.sessionTTL }

func ListenRelay(
	ctx context.Context, relayAddr string, opts ...Option,
) (*ListenResult, error) {
	ws, err := dialWS(ctx, fmt.Sprintf("ws://%s/ws", relayAddr), nil)
	if err != nil {
		return nil, fmt.Errorf("relay ws dial: %w", err)
	}
	return listenHandshake(
		ctx,
		&wsAdapter{conn: ws, ctx: ctx},
		func() { ws.Close(websocket.StatusNormalClosure, "exchange failed") },
		opts...,
	)
}

func ListenRelayWSS(
	ctx context.Context, relayAddr string, tlsCfg *tls.Config, opts ...Option,
) (*ListenResult, error) {
	dopts := &websocket.DialOptions{
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsCfg,
			},
		},
	}
	ws, err := dialWS(ctx, fmt.Sprintf("wss://%s/ws", relayAddr), dopts)
	if err != nil {
		return nil, fmt.Errorf("relay wss dial: %w", err)
	}
	return listenHandshake(
		ctx,
		&wsAdapter{conn: ws, ctx: ctx},
		func() { ws.Close(websocket.StatusNormalClosure, "exchange failed") },
		opts...,
	)
}

func ListenRelayTCP(
	ctx context.Context, relayAddr string, opts ...Option,
) (*ListenResult, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", relayAddr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial: %w", err)
	}
	adapter := newTCPAdapter(conn)
	return listenHandshake(ctx, adapter, func() { conn.Close() }, opts...)
}

func ListenRelayTLS(
	ctx context.Context, relayAddr string, tlsCfg *tls.Config, opts ...Option,
) (*ListenResult, error) {
	var d net.Dialer
	conn, err := tls.DialWithDialer(&d, "tcp", relayAddr, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("tls dial: %w", err)
	}
	adapter := newTLSAdapter(conn)
	return listenHandshake(ctx, adapter, func() { conn.Close() }, opts...)
}
func listenHandshake(
	ctx context.Context,
	rw exchange.ReadWriter,
	closeFn func(),
	opts ...Option,
) (_ *ListenResult, retErr error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}

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
			Mode:  pb.Register_MODE_CREATE,
			Token: o.token,
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
	token := reg.GetToken()
	if err := checkRegisteredToken(token, o.token); err != nil {
		return nil, err
	}

	ttl := time.Duration(reg.GetTtlSeconds()) * time.Second
	sessionTTL := time.Duration(reg.GetSessionTtlSeconds()) * time.Second

	ctx, cancel := context.WithCancel(ctx)
	l := &RelayListener{
		channel:    ch,
		accept:     make(chan *RelayConn, 1),
		ctx:        ctx,
		cancel:     cancel,
		closeFn:    func() { ch.Close() },
		ttl:        ttl,
		sessionTTL: sessionTTL,
	}

	go l.readPump()
	return &ListenResult{
		Listener:   l,
		Token:      token,
		TTL:        ttl,
		SessionTTL: sessionTTL,
	}, nil
}

// Accept waits for the first frame of a new session from the relay. It
// returns net.ErrClosed once the listener has been stopped or released.
// A call that is already blocked when Stop runs returns when the relay
// session is released: at once if no connection is active, otherwise
// when the active connection closes.
func (l *RelayListener) Accept() (kamune.Conn, error) {
	if l.stopped.Load() {
		return nil, net.ErrClosed
	}
	select {
	case rc := <-l.accept:
		return rc, nil
	case <-l.ctx.Done():
		return nil, net.ErrClosed
	}
}

func (l *RelayListener) Close() error {
	l.mu.Lock()
	conn := l.conn
	l.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
	l.release()
	return nil
}

// Stop prevents new connections from being accepted. An active
// connection keeps working, and the relay session (the exchange channel
// and its readPump) is released when that connection closes. With no
// active connection, Stop releases the relay session at once and a
// blocked Accept returns net.ErrClosed. A connection the relay delivered
// but Accept has not returned yet is closed.
func (l *RelayListener) Stop() {
	l.mu.Lock()
	l.stopped.Store(true)
	var pending *RelayConn
	select {
	case pending = <-l.accept:
	default:
	}
	idle := l.conn == nil || l.conn == pending
	l.mu.Unlock()

	if pending != nil {
		pending.Close()
	}
	if idle {
		l.release()
	}
}

// release cancels the listener context, which ends any connection
// derived from it, and closes the exchange channel to the relay once.
func (l *RelayListener) release() {
	l.cancel()
	l.closeOnce.Do(func() {
		if l.closeFn != nil {
			l.closeFn()
		}
	})
}

// readPump reads frames from the relay until the channel fails. On exit
// it releases the relay session so the socket does not linger.
func (l *RelayListener) readPump() {
	defer l.release()
	for {
		data, err := l.channel.ReadBytes()
		if err != nil {
			return
		}
		var frame pb.Frame
		if err := proto.Unmarshal(data, &frame); err != nil {
			slog.Error("relayconn: unmarshal frame", slog.Any("error", err))
			continue
		}
		switch v := frame.Kind.(type) {
		case *pb.Frame_Msg:
			l.deliver(v.Msg)
		case *pb.Frame_Ping:
			pong := &pb.Frame{Kind: &pb.Frame_Pong{Pong: &pb.Pong{}}}
			b, _ := proto.Marshal(pong)
			l.channelMu.Lock()
			l.channel.WriteBytes(b)
			l.channelMu.Unlock()
		case *pb.Frame_Pong:
		}
	}
}

func (l *RelayListener) deliver(msg *pb.Message) {
	data := msg.GetData()

	l.mu.Lock()

	// Always deliver to an existing connection, even after Stop().
	// pushData can block until the consumer drains the buffer, so it
	// runs without l.mu: closing the connection takes l.mu.
	if conn := l.conn; conn != nil {
		l.mu.Unlock()
		conn.pushData(data)
		return
	}

	// If stopped and no active connection, drop the data.
	if l.stopped.Load() {
		l.mu.Unlock()
		return
	}

	rc := newRelayConn(l.ctx, l.channel, &l.channelMu)
	rc.closeFn = func() {
		l.mu.Lock()
		if l.conn == rc {
			l.conn = nil
		}
		stopped := l.stopped.Load()
		l.mu.Unlock()
		if stopped {
			l.release()
		}
	}
	// The buffer is empty, so this does not block.
	rc.pushData(data)

	// Publish the connection and queue it for Accept under l.mu, so
	// Stop sees either both or neither.
	select {
	case l.accept <- rc:
		l.conn = rc
		l.mu.Unlock()
	default:
		l.mu.Unlock()
		slog.Warn("relayconn: accept channel full, dropping session")
		rc.cancel()
	}
}
