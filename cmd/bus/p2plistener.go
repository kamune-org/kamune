package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/kamune-org/kamune"
	relaybroker "github.com/kamune-org/kamune/pkg/relayconn/broker"
	"github.com/xtaci/kcp-go/v5"
)

// p2pListener is a kamune.Listener that registers on the broker and yields
// inbound connections from peers that hole-punch the punch socket. Used for
// UDP+P2P mode in StartServer — replaces the regular kcp.Listener that
// ServeWithUDP would create.
//
// The listener owns a single UDP socket (the punch socket) bound to bindAddr
// (default ":0"), which carries both the broker's packets and the peers'
// KCP packets. kcp-go reads it through a punchFilter: the broker's
// NOTIFY(PEER_MATCHED) for one of the listener's tokens tells the listener
// where the matched peer is, and the listener then kicks that address, to
// open its own NAT to the peer, and takes KCP packets from the peer's IP
// address. Every other packet is dropped before kcp-go sees it.
type p2pListener struct {
	bindAddr   string
	broker     *BrokerClient
	brokerAddr string
	// token is the listener's own token, precomputed (static) or
	// broker-assigned (random), which it registered first.
	token []byte
	// tokens are the tokens the listener registers with the broker and
	// the peers they admit; see admitsPeer. tokenMu guards it.
	tokens  []listenerToken
	tokenMu sync.RWMutex
	// brokerUDP is the broker's address. claimIP and claimPort are the
	// punch socket's address as the broker saw it at start, which every
	// REGISTER claims. The broker only checks the claim's form: it
	// records the address the REGISTER came from.
	brokerUDP *net.UDPAddr
	claimIP   net.IP
	claimPort uint16

	conn   *net.UDPConn
	filter *punchFilter
	kcp    *kcp.Listener

	// kicking holds the peer addresses the listener sends NAT kicks
	// to; kickMu guards it.
	kicking map[netip.AddrPort]struct{}
	kickMu  sync.Mutex

	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
	closeErr  error
}

// listenerToken is a token that a p2pListener registers with the broker,
// with the key of the peer it was derived for, or nil for a random token,
// which admits any peer.
type listenerToken struct {
	token []byte
	peer  []byte
}

// newP2PListener starts a listener that registers token with the broker
// at brokerAddr, or a token the broker assigns when token is empty.
// peerKey is the key of the peer a static token was derived for, or nil
// to admit any peer through the token.
func newP2PListener(
	broker *BrokerClient,
	brokerAddr string,
	token, peerKey []byte,
	bindAddr string,
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
		token:      token,
		conn:       conn,
		kicking:    make(map[netip.AddrPort]struct{}),
		ctx:        ctx,
		cancel:     cancel,
	}

	brokerUDPAddr, err := net.ResolveUDPAddr("udp4", brokerAddr)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("resolve broker: %w", err)
	}
	client, err := broker.Client(brokerAddr)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("broker client: %w", err)
	}

	// ECHO from the punch socket so the broker learns the punch socket's
	// external address:port. This is the address the peer will punch to.
	// EchoOn takes only the broker's reply, within 2s.
	claimIP, claimPort, err := client.EchoOn(ctx, conn)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("broker echo: %w", err)
	}
	l.brokerUDP, l.claimIP, l.claimPort = brokerUDPAddr, claimIP, claimPort

	// REGISTER on the broker with the punch socket's broker-view as the
	// claim address. The peer learns this address via the broker's
	// NOTIFY(PEER_MATCHED) and punches to it.
	pkt := relaybroker.BuildRegister(
		token, client.PublicKey(), claimIP, claimPort,
	)
	if _, err := conn.WriteToUDP(pkt, brokerUDPAddr); err != nil {
		l.Close()
		return nil, fmt.Errorf("send register: %w", err)
	}

	// Random-token mode (token == nil): the broker assigns a token and
	// replies with NOTIFY(TOKEN_ASSIGNED). Pre-read the punch socket
	// before kcp-go starts reading it, since the filter in front of
	// kcp-go acts only on PEER_MATCHED.
	if len(token) == 0 {
		to, cancel := context.WithTimeout(ctx, 2*time.Second)
		assigned, err := readTokenAssigned(to, conn, broker, brokerUDPAddr)
		cancel()
		if err != nil {
			l.Close()
			return nil, fmt.Errorf("read assigned token: %w", err)
		}
		l.token = assigned
	}
	l.tokens = []listenerToken{{token: l.token, peer: peerKey}}

	// Reset the punch socket's deadline before handing it to kcp-go.
	// readTokenAssigned sets a read deadline; if we don't
	// clear it, the kcp-go monitor's first ReadFrom would time out,
	// call notifyReadError, and break the listener (causing the kamune
	// server's Accept loop to spin).
	if err := conn.SetDeadline(time.Time{}); err != nil {
		l.Close()
		return nil, fmt.Errorf("reset punch socket deadline: %w", err)
	}

	// Start kcp-go's Listener on the punch socket. kcp.ServeConn does NOT
	// take ownership of the conn — the listener's Close() does not close
	// the underlying conn; we close it ourselves in p2pListener.Close().
	if err := l.serve(); err != nil {
		l.Close()
		return nil, fmt.Errorf("kcp listener: %w", err)
	}

	// Refresh the broker registration every 30s (half the broker's 60s
	// TTL) so the dialer can find us. Runs until the listener is closed.
	go l.refreshLoop()

	return l, nil
}

// serve starts kcp-go on the punch socket behind a punchFilter, which
// hands the broker's packets to handleBroker.
func (l *p2pListener) serve() error {
	return l.serveWith(kcp.ServeConn)
}

// kcpServeFunc starts kcp-go on a packet conn, as kcp.ServeConn does.
type kcpServeFunc func(
	block kcp.BlockCrypt, dataShards, parityShards int, conn net.PacketConn,
) (*kcp.Listener, error)

// serveWith is serve with serveConn in place of kcp.ServeConn. kcp-go
// reads the punch socket, and so may call handleBroker, before
// serveConn returns, so l.filter is set before it starts.
func (l *p2pListener) serveWith(serveConn kcpServeFunc) error {
	f := newPunchFilter(l.conn)
	if ap, ok := addrPortOf(l.brokerUDP); ok {
		f.broker = ap
	}
	f.onBroker = l.handleBroker
	l.filter = f
	kcpL, err := serveConn(nil, 0, 0, f)
	if err != nil {
		return err
	}
	l.kcp = kcpL
	return nil
}

// Accept blocks until a peer punches the punch socket and completes a KCP
// handshake, then returns the resulting kamune.Conn. The filter takes the
// session's packets until the conn is closed.
func (l *p2pListener) Accept() (kamune.Conn, error) {
	sess, err := l.kcp.AcceptKCP()
	if err != nil {
		return nil, err
	}
	held := &heldSession{
		UDPSession: sess, release: l.filter.hold(sess.RemoteAddr()),
	}
	return &gatedConn{Conn: kamune.NewConn(held), gate: l}, nil
}

// heldSession is a KCP session that a punchFilter takes packets for
// until the session is closed.
type heldSession struct {
	*kcp.UDPSession
	release func()
}

func (s *heldSession) Close() error {
	s.release()
	return s.UDPSession.Close()
}

// handleBroker reads a packet from the broker. A NOTIFY(PEER_MATCHED)
// for one of the listener's tokens has the filter expect the matched
// peer, and starts NAT kicks to the peer's address, so that the peer's
// packets get through a NAT that only lets replies in.
func (l *p2pListener) handleBroker(pkt []byte) {
	p, err := l.broker.parseNotify(pkt)
	if err != nil || p.Type != relaybroker.NotifyPeerMatched {
		return
	}
	if !l.registers(p.Token) {
		return
	}
	ip, ok := netip.AddrFromSlice(p.IP)
	if !ok || p.Port == 0 {
		return
	}
	ip = ip.Unmap()
	l.filter.expect(ip)
	l.kick(netip.AddrPortFrom(ip, p.Port))
}

// registers reports whether notified, the token of a NOTIFY, is one of
// the tokens the listener registers.
func (l *p2pListener) registers(notified []byte) bool {
	l.tokenMu.RLock()
	defer l.tokenMu.RUnlock()
	return slices.ContainsFunc(l.tokens, func(t listenerToken) bool {
		return relaybroker.TokenMatches(notified, t.token)
	})
}

// kick sends NAT kicks to dst for kickDuration, unless it already does,
// or kicks maxMatchedPeers addresses, or the listener is closed.
func (l *p2pListener) kick(dst netip.AddrPort) {
	l.kickMu.Lock()
	_, busy := l.kicking[dst]
	if busy || len(l.kicking) >= maxMatchedPeers || l.ctx.Err() != nil {
		l.kickMu.Unlock()
		return
	}
	l.kicking[dst] = struct{}{}
	l.kickMu.Unlock()
	go func() {
		defer func() {
			l.kickMu.Lock()
			delete(l.kicking, dst)
			l.kickMu.Unlock()
		}()
		peer := net.UDPAddrFromAddrPort(dst)
		kickFor(l.ctx, l.conn, peer, kickDuration)
	}()
}

// admitsPeer reports whether a token the listener registers admits the
// peer whose key is key: a random token, or a static token derived for
// that peer; see peerGate. A KCP session does not tell which token its
// peer matched on, so this holds for the listener as a whole: while any
// random token is registered, every peer is admitted, the peer of a
// removed static token included. A removed token admits no peer of its
// own, and a listener whose tokens are all removed admits no peer.
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

// Close releases the punch socket and stops the kcp-go listener. Safe to
// call multiple times.
func (l *p2pListener) Close() error {
	l.closeOnce.Do(func() {
		l.cancel()
		if l.kcp != nil {
			_ = l.kcp.Close()
		}
		if l.conn != nil {
			l.closeErr = l.conn.Close()
		}
	})
	return l.closeErr
}

// Token returns the hex-encoded broker token (assigned for random mode,
// precomputed for static mode). Empty string when not yet initialized.
func (l *p2pListener) Token() string {
	if len(l.token) == 0 {
		return ""
	}
	return hex.EncodeToString(l.token)
}

// Addr returns the punch socket's local address. Useful for logging and
// share-card display.
func (l *p2pListener) Addr() *net.UDPAddr {
	if l.conn == nil {
		return nil
	}
	if addr, ok := l.conn.LocalAddr().(*net.UDPAddr); ok {
		return addr
	}
	return nil
}

// refreshLoop re-registers the p2pListener's token on the broker every
// 30s (half the broker's default 60s TTL). Runs until the listener is
// closed via Close().
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

// RegisterToken registers an additional token from the punch socket and
// keeps it registered until UnregisterToken removes it. peer is the key
// of the peer a static token was derived for, or nil for a random token.
// A token that is already registered is only sent again. A new token is
// refused with ErrTooManyP2PTokens, and not sent, while the listener
// registers maxP2PTokens tokens.
func (l *p2pListener) RegisterToken(token, peer []byte) error {
	added, err := l.addToken(token, peer)
	if err != nil {
		return err
	}
	if err := l.sendRegister(token); err != nil {
		if added {
			l.UnregisterToken(token)
		}
		return err
	}
	return nil
}

// addToken adds token, for peer, to the tokens the listener registers and
// reports whether it was new. It holds the cap of maxP2PTokens.
func (l *p2pListener) addToken(token, peer []byte) (bool, error) {
	l.tokenMu.Lock()
	defer l.tokenMu.Unlock()
	if slices.ContainsFunc(l.tokens, func(t listenerToken) bool {
		return bytes.Equal(t.token, token)
	}) {
		return false, nil
	}
	if len(l.tokens) >= maxP2PTokens {
		return false, ErrTooManyP2PTokens
	}
	l.tokens = append(l.tokens, listenerToken{
		token: bytes.Clone(token), peer: bytes.Clone(peer),
	})
	return true, nil
}

// sendRegister sends a REGISTER for token from the punch socket, with the
// claim address the listener learned at start. It needs no STUN_ECHO, so
// a broker that drops an echo does not stop a registration or refresh.
func (l *p2pListener) sendRegister(token []byte) error {
	client, err := l.broker.Client(l.brokerAddr)
	if err != nil {
		return fmt.Errorf("broker client: %w", err)
	}
	pkt := relaybroker.BuildRegister(
		token, client.PublicKey(), l.claimIP, l.claimPort,
	)
	if _, err := l.conn.WriteToUDP(pkt, l.brokerUDP); err != nil {
		return fmt.Errorf("send register: %w", err)
	}
	return nil
}

// UnregisterToken stops registering token, the listener's own token or
// one that RegisterToken added, with the broker. The peer of a removed
// static token is then turned away unless another registered token
// admits it, as a random token admits any peer; see admitsPeer. It
// reports whether the token was registered. The broker cannot drop a
// registration on request; it forgets the token once the last
// registration expires.
func (l *p2pListener) UnregisterToken(token []byte) bool {
	l.tokenMu.Lock()
	defer l.tokenMu.Unlock()
	n := len(l.tokens)
	l.tokens = slices.DeleteFunc(l.tokens, func(t listenerToken) bool {
		return bytes.Equal(t.token, token)
	})
	return len(l.tokens) != n
}

// liveTokens returns the tokens the listener registers.
func (l *p2pListener) liveTokens() [][]byte {
	l.tokenMu.RLock()
	defer l.tokenMu.RUnlock()
	out := make([][]byte, 0, len(l.tokens))
	for _, t := range l.tokens {
		out = append(out, t.token)
	}
	return out
}

// refreshRegistration re-sends the REGISTER of every token the listener
// registers from the punch socket, with the same claim address. This
// keeps the broker's registrations active.
func (l *p2pListener) refreshRegistration() error {
	for _, tok := range l.liveTokens() {
		if len(tok) == 0 {
			continue
		}
		if err := l.sendRegister(tok); err != nil {
			return err
		}
	}
	return nil
}

// readTokenAssigned reads from conn looking for a NOTIFY(TOKEN_ASSIGNED)
// packet from the broker. Returns the 16-byte assigned token. Used by
// p2pListener in random mode to capture the broker-assigned token before
// kcp.ServeConn starts reading from the same socket.
func readTokenAssigned(
	ctx context.Context, conn *net.UDPConn,
	broker *BrokerClient, brokerAddr *net.UDPAddr,
) ([]byte, error) {
	buf := make([]byte, 1500)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			return nil, fmt.Errorf("set deadline: %w", err)
		}
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return nil, fmt.Errorf("read notify: %w", err)
		}
		// Only accept packets from the broker.
		if src.IP.Equal(brokerAddr.IP) && src.Port == brokerAddr.Port {
			payload, err := broker.parseNotify(buf[:n])
			if err != nil {
				continue
			}
			if payload.Type == relaybroker.NotifyTokenAssigned {
				return payload.Token, nil
			}
		}
	}
}
