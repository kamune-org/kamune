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
	ws, _, err := websocket.Dial(ctx, fmt.Sprintf("ws://%s/ws", relayAddr), nil)
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
	ws, _, err := websocket.Dial(ctx, fmt.Sprintf("wss://%s/ws", relayAddr), dopts)
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
	token := relayFrame.GetRegistered().GetToken()
	if token == nil {
		return nil, fmt.Errorf("relay returned empty token")
	}

	reg := relayFrame.GetRegistered()
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
	if l.conn != nil {
		l.conn.Close()
	}
	l.mu.Unlock()
	l.cancel()
	l.closeOnce.Do(func() {
		if l.closeFn != nil {
			l.closeFn()
		}
	})
	return nil
}

// Stop prevents new connections from being accepted without closing the
// active connection or the shared exchange channel. The channel and readPump
// remain alive until the active connection closes naturally, at which point
// the exchange channel is cleaned up.
func (l *RelayListener) Stop() {
	l.stopped.Store(true)
	select {
	case rc := <-l.accept:
		rc.Close()
	default:
	}
}

func (l *RelayListener) readPump() {
	defer l.cancel()
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
	if l.conn != nil {
		l.conn.pushData(data)
		l.mu.Unlock()
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
		l.conn = nil
		stopped := l.stopped.Load()
		l.mu.Unlock()
		if stopped {
			l.cancel()
			l.closeOnce.Do(func() {
				if l.closeFn != nil {
					l.closeFn()
				}
			})
		}
	}
	l.conn = rc
	rc.pushData(data)
	l.mu.Unlock()

	select {
	case l.accept <- rc:
	default:
		slog.Warn("relayconn: accept channel full, dropping session")
		l.mu.Lock()
		l.conn = nil
		l.mu.Unlock()
	}
}
