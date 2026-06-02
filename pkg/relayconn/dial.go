package relayconn

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"

	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/relayconn/pb"
)

func DialRelay(ctx context.Context, relayAddr string, token []byte, opts ...Option) (*RelayConn, error) {
	ws, _, err := websocket.Dial(ctx, fmt.Sprintf("ws://%s/ws", relayAddr), nil)
	if err != nil {
		return nil, fmt.Errorf("relay ws dial: %w", err)
	}
	adapter := &wsAdapter{conn: ws, ctx: ctx}
	return relayHandshake(ctx, adapter, token, func() { ws.Close(websocket.StatusNormalClosure, "exchange failed") }, opts...)
}

func DialRelayWSS(ctx context.Context, relayAddr string, token []byte, tlsCfg *tls.Config, opts ...Option) (*RelayConn, error) {
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
	adapter := &wsAdapter{conn: ws, ctx: ctx}
	return relayHandshake(ctx, adapter, token, func() { ws.Close(websocket.StatusNormalClosure, "exchange failed") }, opts...)
}

func DialRelayTCP(ctx context.Context, relayAddr string, token []byte, opts ...Option) (*RelayConn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", relayAddr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial: %w", err)
	}
	adapter := &tcpAdapter{conn: conn}
	return relayHandshake(ctx, adapter, token, func() { conn.Close() }, opts...)
}

func DialRelayTLS(ctx context.Context, relayAddr string, token []byte, tlsCfg *tls.Config, opts ...Option) (*RelayConn, error) {
	var d net.Dialer
	conn, err := tls.DialWithDialer(&d, "tcp", relayAddr, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("tls dial: %w", err)
	}
	adapter := &tlsAdapter{conn: conn}
	return relayHandshake(ctx, adapter, token, func() { conn.Close() }, opts...)
}

func relayHandshake(
	ctx context.Context,
	rw exchange.ReadWriter,
	token []byte,
	closeFn func(),
	opts ...Option,
) (*RelayConn, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}

	ch, err := exchange.Initiate(rw)
	if err != nil {
		closeFn()
		return nil, fmt.Errorf("hpke initiate: %w", err)
	}

	if o.password != "" {
		if err := sendAuth(ch, o.password); err != nil {
			ch.Close()
			return nil, err
		}
	}

	registerFrame := &pb.Frame{
		Kind: &pb.Frame_Register{
			Register: &pb.Register{Token: token},
		},
	}
	regBytes, err := proto.Marshal(registerFrame)
	if err != nil {
		ch.Close()
		return nil, fmt.Errorf("marshal register: %w", err)
	}
	if err := ch.WriteBytes(regBytes); err != nil {
		ch.Close()
		return nil, fmt.Errorf("send register: %w", err)
	}

	relayBytes, err := ch.ReadBytes()
	if err != nil {
		ch.Close()
		return nil, fmt.Errorf("read registered: %w", err)
	}
	var relayFrame pb.Frame
	if err := proto.Unmarshal(relayBytes, &relayFrame); err != nil {
		ch.Close()
		return nil, fmt.Errorf("unmarshal registered: %w", err)
	}
	if relayFrame.GetRegistered() == nil {
		ch.Close()
		return nil, fmt.Errorf("unexpected frame: expected registered, got %T", relayFrame.Kind)
	}

	var mu sync.Mutex
	rc := newRelayConn(ctx, ch, &mu)
	rc.closeFn = func() { ch.Close() }

	go rc.readPump()
	return rc, nil
}
