package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"maps"
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
	// held is set when id comes from BrokerClient.identity, which the
	// listener releases once it stops registering the token.
	held bool
}

// matchedPeerIdle is how long a p2p listener lets packets in from a
// host that a PEER_MATCHED named, after the match and after the last
// packet from it. A live session's keepalives, every 30 s, keep its
// host in.
const matchedPeerIdle = 10 * time.Minute

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

	// peers holds the hosts that a PEER_MATCHED for one of the tokens
	// named, and until when packets from each are let in.
	peers   map[netip.Addr]time.Time
	peersMu sync.Mutex

	conn *net.UDPConn
	kcp  *kcp.Listener

	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
	closeErr  error
}

// newP2PListener binds a punch socket at bindAddr and registers token
// from it with the broker at brokerAddr, or a token that the broker
// assigns when token is empty. It refreshes the registrations of its
// tokens every p2pTokenRefreshInterval and calls onRefresh, if not nil,
// after each refresh that went out.
func newP2PListener(
	broker *BrokerClient, brokerAddr string, token []byte, bindAddr string,
	onRefresh func(l *p2pListener, at time.Time),
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
		peers:      make(map[netip.Addr]time.Time),
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
	claimIP, claimPort, err := broker.echoFrom(ctx, conn, brokerUDPAddr)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("broker echo: %w", err)
	}
	l.claimIP, l.claimPort = claimIP, claimPort

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

	kcpL, err := kcp.ServeConn(nil, 0, 0, &punchConn{l: l})
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
// under the broker identity that BrokerClient keeps for it.
func (l *p2pListener) RegisterToken(token []byte) error {
	id, err := l.broker.identity(l.brokerAddr, token)
	if err != nil {
		return fmt.Errorf("broker client: %w", err)
	}
	t := listenerToken{token: token, id: id, held: true}
	pkt := relaybroker.BuildRegister(
		token, id.PublicKey(), l.claimIP, l.claimPort,
	)
	if _, err := l.conn.WriteToUDP(pkt, l.brokerUDP); err != nil {
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

// fromBroker reports whether src is the broker's address.
func (l *p2pListener) fromBroker(src *net.UDPAddr) bool {
	return src.Port == l.brokerUDP.Port && src.IP.Equal(l.brokerUDP.IP)
}

// handleBroker handles a packet from the broker. A PEER_MATCHED for one
// of the listener's tokens names the dialer that the broker matched with
// it: the listener lets packets from the dialer's host in and punches
// toward the dialer, so that a NAT in front of the listener that only
// lets in replies to its own packets lets the dialer's packets in.
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
		l.admitPeer(ip)
		go func() { _, _ = sendNATKick(l.ctx, l.conn, peer) }()
		return
	}
}

// admitPeer lets packets from host ip in for matchedPeerIdle. It admits
// the host, not its address and port: behind a NAT that maps each
// destination to a port of its own, the dialer's packets come from
// another port than the one the broker saw.
func (l *p2pListener) admitPeer(ip netip.Addr) {
	now := time.Now()
	l.peersMu.Lock()
	defer l.peersMu.Unlock()
	maps.DeleteFunc(l.peers, func(_ netip.Addr, until time.Time) bool {
		return now.After(until)
	})
	l.peers[ip.Unmap()] = now.Add(matchedPeerIdle)
}

// admitted reports whether packets from src are let in, and keeps its
// host in for matchedPeerIdle if so.
func (l *p2pListener) admitted(src *net.UDPAddr) bool {
	ip := src.AddrPort().Addr().Unmap()
	now := time.Now()
	l.peersMu.Lock()
	defer l.peersMu.Unlock()
	until, ok := l.peers[ip]
	if !ok || now.After(until) {
		return false
	}
	l.peers[ip] = now.Add(matchedPeerIdle)
	return true
}

// punchConn is a p2p listener's punch socket as KCP reads it. KCP starts
// a session for any packet from a new address, so punchConn hands the
// broker's packets to the listener instead and drops those from hosts
// that no PEER_MATCHED named.
//
// It must not have the methods of *net.UDPConn that kcp-go looks for to
// read the socket in batches, which would skip ReadFrom.
type punchConn struct {
	l *p2pListener
}

func (c *punchConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, src, err := c.l.conn.ReadFromUDP(b)
		if err != nil {
			return n, nil, err
		}
		switch {
		case c.l.fromBroker(src):
			c.l.handleBroker(b[:n])
		case c.l.admitted(src):
			return n, src, nil
		}
	}
}

func (c *punchConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return c.l.conn.WriteTo(b, addr)
}

func (c *punchConn) Close() error { return c.l.conn.Close() }

func (c *punchConn) LocalAddr() net.Addr { return c.l.conn.LocalAddr() }

func (c *punchConn) SetDeadline(t time.Time) error {
	return c.l.conn.SetDeadline(t)
}

func (c *punchConn) SetReadDeadline(t time.Time) error {
	return c.l.conn.SetReadDeadline(t)
}

func (c *punchConn) SetWriteDeadline(t time.Time) error {
	return c.l.conn.SetWriteDeadline(t)
}
