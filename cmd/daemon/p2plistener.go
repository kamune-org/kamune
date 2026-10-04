package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/kamune-org/kamune"
	relaybroker "github.com/kamune-org/kamune/pkg/relayconn/broker"
	"github.com/xtaci/kcp-go/v5"
)

// listenerToken is a token that a p2p listener registers with the
// broker, and the broker identity it registers it under.
type listenerToken struct {
	token []byte
	id    *relaybroker.Client
	// held is set when id comes from BrokerClient.identity, which the
	// listener releases once it stops registering the token.
	held bool
}

type p2pListener struct {
	bindAddr   string
	broker     *BrokerClient
	brokerAddr string
	// token is the listener's own token, which it registered first.
	token []byte
	// tokens are the tokens that the listener registers.
	tokens  []listenerToken
	tokenMu sync.RWMutex

	conn *net.UDPConn
	kcp  *kcp.Listener

	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
	closeErr  error
}

func newP2PListener(
	broker *BrokerClient, brokerAddr string, token []byte, bindAddr string,
) (*p2pListener, error) {
	if broker == nil {
		return nil, fmt.Errorf("broker is required")
	}
	if bindAddr == "" {
		bindAddr = ":0"
	}
	udpAddr, err := net.ResolveUDPAddr("udp4", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve bind addr: %w", err)
	}
	conn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("bind punch socket: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	l := &p2pListener{
		bindAddr:   bindAddr,
		broker:     broker,
		brokerAddr: brokerAddr,
		conn:       conn,
		ctx:        ctx,
		cancel:     cancel,
	}

	brokerUDPAddr, err := net.ResolveUDPAddr("udp4", brokerAddr)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("resolve broker: %w", err)
	}
	claimIP, claimPort, err := broker.echoFrom(ctx, conn, brokerUDPAddr)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("broker echo: %w", err)
	}

	// A static token has the identity that BrokerClient keeps for it. A
	// random one, which the broker assigns anew, gets a new identity.
	own := listenerToken{held: len(token) > 0}
	if own.held {
		own.id, err = broker.identity(brokerAddr, token)
	} else {
		own.id, err = newBrokerIdentity(brokerAddr)
	}
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("broker client: %w", err)
	}
	if own.held {
		l.tokens = []listenerToken{{token: token, id: own.id, held: true}}
	}
	// Without a token, the broker assigns one; RegisterOn waits for it.
	rctx, rcancel := context.WithTimeout(ctx, 2*time.Second)
	token, err = own.id.RegisterOn(rctx, conn, token, claimIP, claimPort)
	rcancel()
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("broker register: %w", err)
	}
	own.token = token
	l.token = token
	l.tokens = []listenerToken{own}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		l.Close()
		return nil, fmt.Errorf("reset punch socket deadline: %w", err)
	}

	kcpL, err := kcp.ServeConn(nil, 0, 0, conn)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("kcp listener: %w", err)
	}
	l.kcp = kcpL

	go l.refreshLoop()

	return l, nil
}

func (l *p2pListener) Accept() (kamune.Conn, error) {
	sess, err := l.kcp.AcceptKCP()
	if err != nil {
		return nil, err
	}
	return kamune.NewConn(sess), nil
}

func (l *p2pListener) Close() error {
	l.closeOnce.Do(func() {
		l.cancel()
		l.tokenMu.Lock()
		for _, t := range l.tokens {
			l.releaseToken(t)
		}
		l.tokens = nil
		l.tokenMu.Unlock()
		if l.kcp != nil {
			_ = l.kcp.Close()
		}
		if l.conn != nil {
			l.closeErr = l.conn.Close()
		}
	})
	return l.closeErr
}

func (l *p2pListener) Token() string {
	if len(l.token) == 0 {
		return ""
	}
	return hex.EncodeToString(l.token)
}

func (l *p2pListener) Addr() *net.UDPAddr {
	if l.conn == nil {
		return nil
	}
	if addr, ok := l.conn.LocalAddr().(*net.UDPAddr); ok {
		return addr
	}
	return nil
}

func (l *p2pListener) refreshLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-l.ctx.Done():
			return
		case <-ticker.C:
			_ = l.refreshRegistration()
		}
	}
}

// wireKey returns the key of token in p2pListener.ids: its wire form,
// in hex.
func wireKey(token []byte) string {
	return hex.EncodeToString(relaybroker.WireToken(token))
}

// releaseToken releases the broker identity of t, if BrokerClient keeps
// it.
func (l *p2pListener) releaseToken(t listenerToken) {
	if t.held {
		l.broker.release(l.brokerAddr, t.token)
	}
}

// RegisterToken registers an additional token from the punch socket,
// under the broker identity that BrokerClient keeps for it.
func (l *p2pListener) RegisterToken(token []byte) error {
	brokerUDPAddr, err := net.ResolveUDPAddr("udp4", l.brokerAddr)
	if err != nil {
		return fmt.Errorf("resolve broker: %w", err)
	}
	claimIP, claimPort, err := l.broker.echoSeparate(l.ctx, l.brokerAddr)
	if err != nil {
		return fmt.Errorf("broker echo: %w", err)
	}
	id, err := l.broker.identity(l.brokerAddr, token)
	if err != nil {
		return fmt.Errorf("broker client: %w", err)
	}
	t := listenerToken{token: token, id: id, held: true}
	pkt := relaybroker.BuildRegister(
		token, id.PublicKey(), claimIP, claimPort,
	)
	if _, err := l.conn.WriteToUDP(pkt, brokerUDPAddr); err != nil {
		l.releaseToken(t)
		return fmt.Errorf("send register: %w", err)
	}
	l.tokenMu.Lock()
	defer l.tokenMu.Unlock()
	if l.ctx.Err() != nil {
		// Closed meanwhile: Close released the tokens it held.
		l.releaseToken(t)
		return net.ErrClosed
	}
	l.tokens = append(l.tokens, t)
	return nil
}

// UnregisterToken stops registering token, the listener's own token or
// one added by RegisterToken, with the broker. The broker has no way to
// drop a registration at once, so it forgets the token when its last
// registration expires.
func (l *p2pListener) UnregisterToken(token []byte) {
	l.tokenMu.Lock()
	defer l.tokenMu.Unlock()
	l.tokens = slices.DeleteFunc(l.tokens, func(t listenerToken) bool {
		if !bytes.Equal(t.token, token) {
			return false
		}
		l.releaseToken(t)
		return true
	})
}

// liveTokens returns the tokens that the listener registers.
func (l *p2pListener) liveTokens() []listenerToken {
	l.tokenMu.RLock()
	defer l.tokenMu.RUnlock()
	return slices.Clone(l.tokens)
}

func (l *p2pListener) refreshRegistration() error {
	brokerUDPAddr, err := net.ResolveUDPAddr("udp4", l.brokerAddr)
	if err != nil {
		return fmt.Errorf("resolve broker: %w", err)
	}
	claimIP, claimPort, err := l.broker.echoSeparate(l.ctx, l.brokerAddr)
	if err != nil {
		return fmt.Errorf("broker echo: %w", err)
	}

	for _, tok := range l.liveTokens() {
		if len(tok.token) == 0 {
			continue
		}
		pkt := relaybroker.BuildRegister(
			tok.token, tok.id.PublicKey(), claimIP, claimPort,
		)
		if _, err := l.conn.WriteToUDP(pkt, brokerUDPAddr); err != nil {
			return fmt.Errorf("send register: %w", err)
		}
	}
	return nil
}
