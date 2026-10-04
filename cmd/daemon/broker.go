package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/xtaci/kcp-go/v5"

	relaybroker "github.com/kamune-org/kamune/pkg/relayconn/broker"
)

var echoRequest = []byte{'K', 'B', 'R', 'K', 0x01, 0x01}

var ErrHolePunchFailed = errors.New("hole-punch failed")

// errNoMatchToken is returned by WaitMatch for an empty token, which no
// PEER_MATCHED can match.
var errNoMatchToken = errors.New("a p2p token is required to match a peer")

const (
	DefaultHolePunchTimeout = 5 * time.Second
	// echoTimeout bounds the wait for the broker's STUN_ECHO reply.
	echoTimeout = 2 * time.Second
	// matchRefreshInterval is how often WaitMatch refreshes its
	// registration while it waits for the peer.
	matchRefreshInterval = 25 * time.Second
)

// brokerIDHold is how long a token's broker identity is kept after its
// last registration ends. The broker keeps a registration for its TTL,
// 60 s by default, after the last REGISTER, and matches a REGISTER of
// the same token under another key with it: a dial retried with a new
// key would be matched with its own stale registration and punch to a
// closed socket. Under the same key the REGISTER refreshes it instead.
const brokerIDHold = 2 * time.Minute

// heldIdentity is the broker identity of one token.
type heldIdentity struct {
	id *relaybroker.Client
	// users counts the registrations that use id.
	users int
	// until is when id may be dropped, once users is zero.
	until time.Time
}

// BrokerClient runs rendezvous with a kamune broker. It holds no broker
// identity of its own: every token is registered under an X25519 key of
// its own (see newBrokerIdentity), so the broker and anyone watching its
// traffic cannot link one token's registrations to another's by key. A
// token's key is kept while the token is registered and for
// brokerIDHold after.
//
// The source address still links registrations: the tokens of one p2p
// listener are registered and refreshed together from its punch socket.
type BrokerClient struct {
	mu sync.Mutex
	// ids holds the identity of each token, by broker address and wire
	// token.
	ids map[string]*heldIdentity
}

func NewBrokerClient() (*BrokerClient, error) {
	return &BrokerClient{ids: make(map[string]*heldIdentity)}, nil
}

// identityKey is the key of the identity of token at brokerAddr in
// BrokerClient.ids.
func identityKey(brokerAddr string, token []byte) string {
	return brokerAddr + "/" + wireKey(token)
}

// identity returns the broker identity to register token under with the
// broker at brokerAddr: the one that the token has, while it is in use
// or held, or a new one. Call release once the registration ends.
func (b *BrokerClient) identity(
	brokerAddr string, token []byte,
) (*relaybroker.Client, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	for k, h := range b.ids {
		if h.users == 0 && now.After(h.until) {
			delete(b.ids, k)
		}
	}
	key := identityKey(brokerAddr, token)
	if h, ok := b.ids[key]; ok {
		h.users++
		return h.id, nil
	}
	id, err := newBrokerIdentity(brokerAddr)
	if err != nil {
		return nil, err
	}
	b.ids[key] = &heldIdentity{id: id, users: 1}
	return id, nil
}

// release ends a registration of token at brokerAddr under the identity
// that identity returned. The identity is held for brokerIDHold once no
// registration uses it.
func (b *BrokerClient) release(brokerAddr string, token []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	h, ok := b.ids[identityKey(brokerAddr, token)]
	if !ok || h.users == 0 {
		return
	}
	h.users--
	if h.users == 0 {
		h.until = time.Now().Add(brokerIDHold)
	}
}

// newBrokerIdentity returns a broker client for the broker at
// brokerAddr with a new X25519 key. A REGISTER carries the key in the
// clear, and the broker needs the same key on every refresh of one
// registration, so use one identity per token, for as long as that
// token is registered, and never for another token.
func newBrokerIdentity(brokerAddr string) (*relaybroker.Client, error) {
	return relaybroker.NewClient(brokerAddr)
}

// WaitMatch registers token with the broker from a new punch socket and
// waits, until ctx ends, for the broker's PEER_MATCHED for it. It returns
// the punch socket, to punch to the matched peer from, and the match.
// The registration is under the token's broker identity, which a retry
// within brokerIDHold gets again.
func (b *BrokerClient) WaitMatch(
	ctx context.Context, brokerAddr string, token []byte,
) (*net.UDPConn, relaybroker.Payload, error) {
	if len(token) == 0 {
		return nil, relaybroker.Payload{}, errNoMatchToken
	}
	id, err := b.identity(brokerAddr, token)
	if err != nil {
		return nil, relaybroker.Payload{}, fmt.Errorf("broker client: %w", err)
	}
	defer b.release(brokerAddr, token)
	punchConn, err := net.ListenUDP(
		"udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0},
	)
	if err != nil {
		return nil, relaybroker.Payload{}, fmt.Errorf("open punch socket: %w", err)
	}

	brokerUDPAddr, err := net.ResolveUDPAddr("udp4", brokerAddr)
	if err != nil {
		punchConn.Close()
		return nil, relaybroker.Payload{}, fmt.Errorf("resolve broker: %w", err)
	}

	claimIP, claimPort, err := b.echoFrom(ctx, punchConn, brokerUDPAddr)
	if err != nil {
		punchConn.Close()
		return nil, relaybroker.Payload{}, fmt.Errorf("broker echo: %w", err)
	}
	if err := punchConn.SetDeadline(time.Time{}); err != nil {
		punchConn.Close()
		return nil, relaybroker.Payload{},
			fmt.Errorf("clear punch deadline: %w", err)
	}

	pkt := relaybroker.BuildRegister(
		token, id.PublicKey(), claimIP, claimPort,
	)
	if _, err := punchConn.WriteToUDP(pkt, brokerUDPAddr); err != nil {
		punchConn.Close()
		return nil, relaybroker.Payload{}, fmt.Errorf("send register: %w", err)
	}

	for {
		// Refresh the registration on the broker every so often, so
		// that it does not expire while we wait for the peer.
		rctx, cancel := context.WithTimeout(ctx, matchRefreshInterval)
		payload, err := id.ReadNotify(rctx, punchConn)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				punchConn.Close()
				return nil, relaybroker.Payload{}, ctx.Err()
			}
			if errors.Is(err, context.DeadlineExceeded) {
				_, _ = punchConn.WriteToUDP(pkt, brokerUDPAddr)
				continue
			}
			punchConn.Close()
			return nil, relaybroker.Payload{}, err
		}
		// The broker echoes the token's 16-byte wire form.
		if payload.Type == relaybroker.NotifyPeerMatched &&
			relaybroker.TokenMatches(payload.Token, token) {
			return punchConn, payload, nil
		}
	}
}

// echoFrom sends a STUN_ECHO from conn and returns the address the broker
// sees for conn. It waits for the reply for at most echoTimeout, and not
// past ctx's deadline.
func (b *BrokerClient) echoFrom(
	ctx context.Context, conn *net.UDPConn, brokerAddr *net.UDPAddr,
) (net.IP, uint16, error) {
	deadline := time.Now().Add(echoTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, 0, fmt.Errorf("set deadline: %w", err)
	}
	if _, err := conn.WriteToUDP(echoRequest, brokerAddr); err != nil {
		return nil, 0, fmt.Errorf("write echo: %w", err)
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, 0, fmt.Errorf("read echo: %w", err)
	}
	return parseEchoResponse(buf[:n])
}

func (b *BrokerClient) echoSeparate(
	ctx context.Context, brokerAddr string,
) (net.IP, uint16, error) {
	udpAddr, err := net.ResolveUDPAddr("udp4", brokerAddr)
	if err != nil {
		return nil, 0, fmt.Errorf("resolve broker: %w", err)
	}
	conn, err := net.DialUDP("udp4", nil, udpAddr)
	if err != nil {
		return nil, 0, fmt.Errorf("dial broker: %w", err)
	}
	defer conn.Close()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(2 * time.Second)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, 0, fmt.Errorf("set deadline: %w", err)
	}
	if _, err := conn.Write(echoRequest); err != nil {
		return nil, 0, fmt.Errorf("write echo: %w", err)
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, 0, fmt.Errorf("read echo: %w", err)
	}
	return parseEchoResponse(buf[:n])
}

func parseEchoResponse(resp []byte) (net.IP, uint16, error) {
	for i, c := range resp {
		if c == 0 {
			resp = resp[:i]
			break
		}
	}
	host, portStr, err := net.SplitHostPort(string(resp))
	if err != nil {
		return nil, 0, fmt.Errorf("malformed echo response %q: %w", resp, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 0, fmt.Errorf("parse ip %q: invalid", host)
	}
	port64, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, 0, fmt.Errorf("parse port %q: %w", portStr, err)
	}
	return ip, uint16(port64), nil
}

func sendNATKick(ctx context.Context, conn *net.UDPConn, peerAddr *net.UDPAddr) {
	for range 5 {
		if ctx.Err() != nil {
			return
		}
		if _, err := conn.WriteToUDP([]byte{0}, peerAddr); err != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (b *BrokerClient) HolePunch(
	ctx context.Context, punchConn *net.UDPConn,
	peerIP net.IP, peerPort uint16, timeout time.Duration,
) (*kcp.UDPSession, error) {
	if timeout <= 0 {
		timeout = DefaultHolePunchTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHolePunchFailed, err)
	}

	peerAddr := &net.UDPAddr{IP: peerIP, Port: int(peerPort)}

	punchCtx, punchCancel := context.WithCancel(ctx)
	defer punchCancel()
	go sendNATKick(punchCtx, punchConn, peerAddr)

	var convid uint32
	if err := binary.Read(rand.Reader, binary.LittleEndian, &convid); err != nil {
		return nil, fmt.Errorf("convid: %w", err)
	}
	sess, err := kcp.NewConn4(convid, peerAddr, nil, 0, 0, true, punchConn)
	if err != nil {
		return nil, fmt.Errorf("kcp session: %w", err)
	}
	return sess, nil
}
