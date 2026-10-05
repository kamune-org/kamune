package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
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
	id    *brokerID
	// peer is the key of the peer that a static token was derived for,
	// or nil for a random token, which admits any peer; see
	// p2pListener.admitsPeer.
	peer []byte
	// held is set when id comes from BrokerClient.identity, which the
	// listener releases once it stops registering the token.
	held bool
}

type p2pListener struct {
	bindAddr   string
	broker     *BrokerClient
	brokerAddr string
	// brokerUDP is brokerAddr, resolved when the listener started. The
	// listener registers with it and takes packets from it as the
	// broker's.
	brokerUDP *net.UDPAddr
	// claimIP and claimPort are the punch socket's address as the broker
	// saw it when the listener started, which every REGISTER claims. The
	// broker only checks the claim's form; it records the REGISTER's
	// source.
	claimIP   net.IP
	claimPort uint16
	// onRefresh, if set, is called after each refresh that sent every
	// token's REGISTER, with the time it began.
	onRefresh func(l *p2pListener, at time.Time)
	// token is the listener's own token, which it registered first.
	token []byte
	// tokens are the tokens that the listener registers.
	tokens  []listenerToken
	tokenMu sync.RWMutex

	conn *net.UDPConn
	// filter is what kcp-go reads the punch socket through; see
	// punchFilter.
	filter *punchFilter
	kcp    *kcp.Listener

	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
	closeErr  error
}

// newP2PListener binds a punch socket at bindAddr and registers token
// from it with the broker at brokerAddr, or a token that the broker
// assigns when token is empty. peerKey is the key of the peer that a
// static token was derived for, or nil. It refreshes the registrations
// of its tokens every p2pTokenRefreshInterval and calls onRefresh, if
// not nil, after each refresh that went out.
func newP2PListener(
	broker *BrokerClient, brokerAddr string, token, peerKey []byte,
	bindAddr string, onRefresh func(l *p2pListener, at time.Time),
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
		onRefresh:  onRefresh,
		conn:       conn,
		ctx:        ctx,
		cancel:     cancel,
	}

	brokerUDPAddr, err := net.ResolveUDPAddr("udp4", brokerAddr)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("resolve broker: %w", err)
	}
	l.brokerUDP = brokerUDPAddr

	// A static token has the identity that BrokerClient keeps for it. A
	// random one, which the broker assigns anew, gets a new identity.
	own := listenerToken{held: len(token) > 0, peer: bytes.Clone(peerKey)}
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
		l.tokens = []listenerToken{{
			token: token, id: own.id, held: true, peer: own.peer,
		}}
	}
	// EchoOn takes only the broker's reply as the echo: a former peer's
	// KCP retransmits, or anyone else's datagram, may reach the socket
	// first.
	ectx, ecancel := context.WithTimeout(ctx, echoTimeout)
	claimIP, claimPort, err := own.id.EchoOn(ectx, conn)
	ecancel()
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("broker echo: %w", err)
	}
	l.claimIP, l.claimPort = claimIP, claimPort
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

	// kcp-go reads the socket, and so may call handleBroker, as soon
	// as it starts, so l.filter is set before.
	f := newPunchFilter(conn)
	if ap, ok := addrPortOf(brokerUDPAddr); ok {
		f.broker = ap
	}
	f.onBroker = l.handleBroker
	l.filter = f
	kcpL, err := kcp.ServeConn(nil, 0, 0, f)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("kcp listener: %w", err)
	}
	l.kcp = kcpL

	go l.refreshLoop()

	return l, nil
}

// Accept returns the next KCP session that a peer opened on the punch
// socket, carrying the listener as its peer gate. The filter passes on
// the session's packets until it is closed.
func (l *p2pListener) Accept() (kamune.Conn, error) {
	sess, err := acceptHeld(l.kcp, l.filter)
	if err != nil {
		return nil, err
	}
	return &gatedConn{Conn: kamune.NewConn(sess), gate: l}, nil
}

// admitsPeer reports whether a token that the listener registers admits
// the peer whose key is key: a random token, or a static token derived
// for that peer. A KCP session does not tell which token its peer
// matched on, so this holds for the listener as a whole: while it
// registers a random token, every peer is admitted, the peer of a
// removed static token too. A listener that registers no token admits
// no peer.
func (l *p2pListener) admitsPeer(key []byte) bool {
	l.tokenMu.RLock()
	defer l.tokenMu.RUnlock()
	for _, t := range l.tokens {
		if t.peer == nil || bytes.Equal(t.peer, key) {
			return true
		}
	}
	return false
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
	ticker := time.NewTicker(p2pTokenRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-l.ctx.Done():
			return
		case <-ticker.C:
			if err := l.refreshRegistration(); err != nil {
				slog.Warn(
					"p2p listener: refresh registrations",
					slog.Any("error", err),
				)
			}
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
// under the broker identity that BrokerClient keeps for it, and keeps it
// registered until UnregisterToken removes it. peer is the key of the
// peer that a static token was derived for, or nil for a random token.
// While the listener registers maxP2PTokens tokens, its own included, a
// new token is refused with errTooManyP2PTokens, and not sent.
func (l *p2pListener) RegisterToken(token, peer []byte) error {
	l.tokenMu.Lock()
	if l.ctx.Err() != nil {
		l.tokenMu.Unlock()
		return net.ErrClosed
	}
	if len(l.tokens) >= maxP2PTokens {
		l.tokenMu.Unlock()
		return errTooManyP2PTokens
	}
	id, err := l.broker.identity(l.brokerAddr, token)
	if err != nil {
		l.tokenMu.Unlock()
		return fmt.Errorf("broker client: %w", err)
	}
	l.tokens = append(l.tokens, listenerToken{
		token: token, id: id, held: true, peer: bytes.Clone(peer),
	})
	l.tokenMu.Unlock()

	pkt := relaybroker.BuildRegister(
		token, id.PublicKey(), l.claimIP, l.claimPort,
	)
	if _, err := l.conn.WriteToUDP(pkt, l.brokerUDP); err != nil {
		l.UnregisterToken(token)
		return fmt.Errorf("send register: %w", err)
	}
	return nil
}

// UnregisterToken stops registering token, the listener's own token or
// one added by RegisterToken, with the broker, and stops letting in the
// peers that the broker matched on it; a session that such a peer opened
// already is kept. The broker has no way to drop a registration at once,
// so it forgets the token when its last registration expires.
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
	if l.filter != nil {
		l.filter.forget(wireKey(token))
	}
}

// liveTokens returns the tokens that the listener registers.
func (l *p2pListener) liveTokens() []listenerToken {
	l.tokenMu.RLock()
	defer l.tokenMu.RUnlock()
	return slices.Clone(l.tokens)
}

// refreshRegistration sends a REGISTER for each of the listener's tokens
// from the punch socket, which keeps the broker's registration alive
// for its TTL, and calls onRefresh once they have all gone out. It does
// not ask the broker for the socket's address first: a refresh needs
// nothing from the broker, and the broker may drop such a request.
func (l *p2pListener) refreshRegistration() error {
	at := time.Now()
	for _, tok := range l.liveTokens() {
		if len(tok.token) == 0 {
			continue
		}
		pkt := relaybroker.BuildRegister(
			tok.token, tok.id.PublicKey(), l.claimIP, l.claimPort,
		)
		if _, err := l.conn.WriteToUDP(pkt, l.brokerUDP); err != nil {
			return fmt.Errorf("send register: %w", err)
		}
	}
	if l.onRefresh != nil {
		l.onRefresh(l, at)
	}
	return nil
}

// handleBroker handles a packet from the broker. A PEER_MATCHED for one
// of the listener's tokens names the dialer that the broker matched with
// it: the listener lets packets from the dialer's host in for
// matchWindow and punches toward the dialer, so that a NAT in front of
// the listener that only lets in replies to its own packets lets the
// dialer's packets in.
func (l *p2pListener) handleBroker(pkt []byte) {
	brokerEphPub, nonce, sealed, err := relaybroker.ParseNotify(pkt)
	if err != nil {
		return
	}
	for _, t := range l.liveTokens() {
		p, err := t.id.openNotify(brokerEphPub, nonce, sealed)
		if err != nil {
			continue
		}
		if p.Type != relaybroker.NotifyPeerMatched ||
			!relaybroker.TokenMatches(p.Token, t.token) {
			return
		}
		ip, ok := netip.AddrFromSlice(p.IP)
		if !ok {
			return
		}
		peer := net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, p.Port))
		l.filter.expect(ip, wireKey(t.token))
		go func() { _, _ = sendNATKick(l.ctx, l.conn, peer) }()
		return
	}
}
