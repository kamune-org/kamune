package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
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
	token      []byte // precomputed (static) or broker-assigned (random)

	conn *net.UDPConn
	kcp  *kcp.Listener

	ctx        context.Context
	cancel     context.CancelFunc
	closeOnce  sync.Once
	closeErr   error
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
	return kamune.NewConn(sess), nil
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
	// The claimIP:claimPort returned is from a different source port
	// than the punch socket, but the broker's self-match path only
	// updates TTL — it doesn't touch the stored addr — so the stored
	// punch-socket address is preserved for peer matching.
	claimIP, claimPort, err := l.broker.echoSeparate(l.ctx, l.brokerAddr)
	if err != nil {
		return fmt.Errorf("broker echo: %w", err)
	}
	client, err := l.broker.Client(l.brokerAddr)
	if err != nil {
		return fmt.Errorf("broker client: %w", err)
	}
	pkt := relaybroker.BuildRegister(
		l.token, client.PublicKey(), claimIP, claimPort,
	)
	if _, err := l.conn.WriteToUDP(pkt, brokerUDPAddr); err != nil {
		return fmt.Errorf("send register: %w", err)
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
