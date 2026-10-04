package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
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
// (default ":0"). It uses the kcp-go Listener (via kcp.ServeConn) on the
// same socket, so any peer that successfully punches and sends KCP packets
// is auto-accepted regardless of source address. Broker NOTIFYs that arrive
// on the same socket are silently dropped by kcp-go (they're not valid KCP
// packets) — the listener doesn't need to read them; the punch socket is
// for KCP traffic only.
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

	conn *net.UDPConn
	kcp  *kcp.Listener

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
		ctx:        ctx,
		cancel:     cancel,
	}

	// ECHO from the punch socket so the broker learns the punch socket's
	// external address:port. This is the address the peer will punch to.
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

	// REGISTER on the broker with the punch socket's broker-view as the
	// claim address. The peer learns this address via the broker's
	// NOTIFY(PEER_MATCHED) and punches to it.
	client, err := broker.Client(brokerAddr)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("broker client: %w", err)
	}
	pkt := relaybroker.BuildRegister(
		token, client.PublicKey(), claimIP, claimPort,
	)
	if _, err := conn.WriteToUDP(pkt, brokerUDPAddr); err != nil {
		l.Close()
		return nil, fmt.Errorf("send register: %w", err)
	}

	// Random-token mode (token == nil): the broker assigns a token and
	// replies with NOTIFY(TOKEN_ASSIGNED). Pre-read the punch socket
	// before starting kcp.ServeConn so we can capture the assigned
	// token without kcp-go swallowing it.
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
	// echoFrom / readTokenAssigned set a 2s read deadline; if we don't
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
	kcpL, err := kcp.ServeConn(nil, 0, 0, conn)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("kcp listener: %w", err)
	}
	l.kcp = kcpL

	// Refresh the broker registration every 30s (half the broker's 60s
	// TTL) so the dialer can find us. Runs until the listener is closed.
	go l.refreshLoop()

	return l, nil
}

// Accept blocks until a peer punches the punch socket and completes a KCP
// handshake, then returns the resulting kamune.Conn.
func (l *p2pListener) Accept() (kamune.Conn, error) {
	sess, err := l.kcp.AcceptKCP()
	if err != nil {
		return nil, err
	}
	return &gatedConn{Conn: kamune.NewConn(sess), gate: l}, nil
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

// sendRegister sends a REGISTER for token from the punch socket.
func (l *p2pListener) sendRegister(token []byte) error {
	brokerUDPAddr, err := net.ResolveUDPAddr("udp4", l.brokerAddr)
	if err != nil {
		return fmt.Errorf("resolve broker: %w", err)
	}
	claimIP, claimPort, err := l.broker.echoSeparate(l.ctx, l.brokerAddr)
	if err != nil {
		return fmt.Errorf("broker echo: %w", err)
	}
	client, err := l.broker.Client(l.brokerAddr)
	if err != nil {
		return fmt.Errorf("broker client: %w", err)
	}
	pkt := relaybroker.BuildRegister(
		token, client.PublicKey(), claimIP, claimPort,
	)
	if _, err := l.conn.WriteToUDP(pkt, brokerUDPAddr); err != nil {
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

// refreshRegistration re-sends the REGISTER packet from the punch socket,
// preserving the same claimIP:claimPort. This keeps the broker's
// registration active.
func (l *p2pListener) refreshRegistration() error {
	brokerUDPAddr, err := net.ResolveUDPAddr("udp4", l.brokerAddr)
	if err != nil {
		return fmt.Errorf("resolve broker: %w", err)
	}
	// Use echoSeparate (fresh socket) so the deadline doesn't leak
	// onto the punch socket (which is shared with kcp-go's monitor).
	claimIP, claimPort, err := l.broker.echoSeparate(l.ctx, l.brokerAddr)
	if err != nil {
		return fmt.Errorf("broker echo: %w", err)
	}
	client, err := l.broker.Client(l.brokerAddr)
	if err != nil {
		return fmt.Errorf("broker client: %w", err)
	}

	for _, tok := range l.liveTokens() {
		if len(tok) == 0 {
			continue
		}
		pkt := relaybroker.BuildRegister(
			tok, client.PublicKey(), claimIP, claimPort,
		)
		if _, err := l.conn.WriteToUDP(pkt, brokerUDPAddr); err != nil {
			return fmt.Errorf("send register: %w", err)
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
