package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
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

// echoRequest is the 6-byte STUN_ECHO packet sent to the broker. The wire
// format is "KBRK" magic + 0x01 ver + 0x01 opcode (see pkg/relayconn/broker
// codec.go for the constants — duplicated here to avoid a new exported helper).
var echoRequest = []byte{'K', 'B', 'R', 'K', 0x01, 0x01}

// ErrHolePunchFailed is returned by HolePunch when the peer's KCP packets
// never arrive on the punch socket within the configured timeout.
var ErrHolePunchFailed = errors.New("hole-punch failed")

// DefaultHolePunchTimeout is how long HolePunch waits for the peer's first
// KCP packet before giving up.
const DefaultHolePunchTimeout = 5 * time.Second

// BrokerClient wraps the kamune broker client with a stable X25519 identity
// that survives across broker-address changes. The X25519 key is created
// eagerly (in NewBrokerClient) so the broker sees the same identity for every
// registration, which is required for its self-match rule. The underlying
// relaybroker.Client is created lazily on first use, since the broker address
// is only known once the user configures a server.
type BrokerClient struct {
	key *ecdh.PrivateKey
	pub []byte

	mu         sync.Mutex
	client     *relaybroker.Client
	brokerAddr string
}

// NewBrokerClient returns a BrokerClient with a freshly-generated X25519
// identity but no underlying network client. The network client is created on
// first call to Client.
func NewBrokerClient() (*BrokerClient, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate x25519 key: %w", err)
	}
	return &BrokerClient{key: k, pub: k.PublicKey().Bytes()}, nil
}

// PublicKey returns the 32-byte X25519 public key.
func (b *BrokerClient) PublicKey() []byte {
	out := make([]byte, len(b.pub))
	copy(out, b.pub)
	return out
}

// Client returns the underlying broker client, creating it on first call
// (or when the broker address changes). The client is bound to the stable
// X25519 key so re-registrations keep the same identity.
func (b *BrokerClient) Client(brokerAddr string) (*relaybroker.Client, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.client != nil && b.brokerAddr == brokerAddr {
		return b.client, nil
	}
	c, err := relaybroker.NewClientWithKey(brokerAddr, b.key)
	if err != nil {
		return nil, err
	}
	b.client = c
	b.brokerAddr = brokerAddr
	return c, nil
}

// WaitMatch opens a UDP punch socket, sends ECHO + REGISTER from it, and
// blocks until a NOTIFY(PEER_MATCHED) arrives on the same socket (or ctx is
// cancelled). Returns the punch socket (caller takes ownership; used as the
// underlying transport for the KCP session in HolePunch) and the payload.
//
// The bus manages the punch socket directly (rather than calling
// Client.Listen, which opens its own socket) so that the same port handles
// both broker NOTIFYs and the peer's KCP packets — required for the
// hole-punch to traverse NATs.
func (b *BrokerClient) WaitMatch(
	ctx context.Context, brokerAddr string, token []byte,
) (*net.UDPConn, relaybroker.Payload, error) {
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

	// ECHO from the punch socket so the broker's view of our address is
	// the punch socket's external address:port (the address the broker
	// will send NOTIFYs to).
	claimIP, claimPort, err := b.echoFrom(ctx, punchConn, brokerUDPAddr)
	if err != nil {
		punchConn.Close()
		return nil, relaybroker.Payload{}, fmt.Errorf("broker echo: %w", err)
	}
	// Clear the echo deadline before sending the REGISTER. echoFrom set
	// a read+write deadline on punchConn; if we don't clear it, the
	// write below would be subject to the same deadline and could fail
	// or block unexpectedly on slow brokers.
	if err := punchConn.SetDeadline(time.Time{}); err != nil {
		punchConn.Close()
		return nil, relaybroker.Payload{},
			fmt.Errorf("clear punch deadline: %w", err)
	}

	// REGISTER from the punch socket. The broker stores the (token, our
	// X25519 pub, claimIP:claimPort) tuple and will match us with a peer
	// that registers with the same token.
	client, err := b.Client(brokerAddr)
	if err != nil {
		punchConn.Close()
		return nil, relaybroker.Payload{}, fmt.Errorf("broker client: %w", err)
	}
	pkt := relaybroker.BuildRegister(
		token, client.PublicKey(), claimIP, claimPort,
	)
	if _, err := punchConn.WriteToUDP(pkt, brokerUDPAddr); err != nil {
		punchConn.Close()
		return nil, relaybroker.Payload{}, fmt.Errorf("send register: %w", err)
	}

	// Read NOTIFYs from the punch socket in a loop. We discard
	// TOKEN_ASSIGNED (random-token mode is handled by RegisterP2PDialer
	// which pre-resolves the token before WaitMatch is called) and
	// return on the first PEER_MATCHED.
	buf := make([]byte, 1500)
	for {
		select {
		case <-ctx.Done():
			punchConn.Close()
			return nil, relaybroker.Payload{}, ctx.Err()
		default:
		}
		if err := punchConn.SetReadDeadline(
			time.Now().Add(500 * time.Millisecond),
		); err != nil {
			punchConn.Close()
			return nil, relaybroker.Payload{}, fmt.Errorf("set read deadline: %w", err)
		}
		n, _, err := punchConn.ReadFromUDP(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			punchConn.Close()
			return nil, relaybroker.Payload{}, fmt.Errorf("read notify: %w", err)
		}
		payload, err := b.parseNotify(buf[:n])
		if err != nil {
			continue
		}
		if payload.Type == relaybroker.NotifyPeerMatched {
			// Validate that the NOTIFY carries the expected
			// token. For static mode (token != nil), the
			// payload must match; for random mode (token ==
			// nil) the broker assigned a fresh token — skip
			// the check.
			if len(token) > 0 && !bytes.Equal(payload.Token, token) {
				continue
			}
			// Clear the read deadline inherited from the NOTIFY
			// loop. If left set, the deadline expires shortly after
			// HolePunch creates the KCP session, causing its
			// readLoop to fail with a timeout and exit — the
			// session can then never receive data.
			_ = punchConn.SetReadDeadline(time.Time{})
			return punchConn, *payload, nil
		}
	}
}

// echoFrom sends a STUN_ECHO from conn to brokerAddr and returns the
// broker's view of conn's source address:port. The bus uses this on the
// punch socket (rather than Client.Echo, which opens a fresh ephemeral
// socket) so the claimIP:claimPort reported to the broker matches the
// punch socket.
//
// WARNING: sets a read deadline on conn. If conn is shared with another
// reader (e.g. the kcp-go monitor on a p2pListener's punch socket),
// the deadline will affect the other reader too. Prefer echoSeparate
// when the conn is shared.
func (b *BrokerClient) echoFrom(
	ctx context.Context, conn *net.UDPConn, brokerAddr *net.UDPAddr,
) (net.IP, uint16, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(2 * time.Second)
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

// echoSeparate sends a STUN_ECHO from a fresh ephemeral UDP socket (not
// from any shared conn). Use this when the caller's conn is shared with
// another reader (e.g. the kcp-go monitor on a p2pListener's punch
// socket) — echoFrom would set a deadline on the shared conn and break
// the other reader.
//
// The returned claimIP:claimPort is the broker's view of the
// ephemeral socket, NOT the shared conn. For cases where the claim
// address must match the shared conn (e.g. the initial broker
// registration of a p2pListener), use echoFrom on a dedicated socket
// instead, or call Register with a claimIP:claimPort captured earlier.
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

// parseNotify decrypts and decodes a NOTIFY packet using the bus's stable
// X25519 key. Mirrors broker.Client.decodeNotify so the bus can read NOTIFYs
// from a caller-owned socket (rather than going through Client.Listen, which
// owns its own socket).
func (b *BrokerClient) parseNotify(pkt []byte) (*relaybroker.Payload, error) {
	brokerEphPub, nonce, sealed, err := relaybroker.ParseNotify(pkt)
	if err != nil {
		return nil, err
	}
	brokerPub, err := ecdh.X25519().NewPublicKey(brokerEphPub)
	if err != nil {
		return nil, err
	}
	shared, err := b.key.ECDH(brokerPub)
	if err != nil {
		return nil, err
	}
	key := sha256.Sum256(shared)
	plaintext, err := relaybroker.OpenNotify(
		key[:], brokerEphPub, nonce, sealed,
	)
	if err != nil {
		return nil, err
	}
	np, err := relaybroker.ParseNotifyPayload(plaintext)
	if err != nil {
		return nil, err
	}
	return &relaybroker.Payload{
		Type:            np.Type,
		Token:           append([]byte(nil), np.Token...),
		OtherPeerEphPub: append([]byte(nil), np.OtherPeerEphPub...),
		IP:              append(net.IP(nil), np.IP...),
		Port:            np.Port,
		TTLSeconds:      np.TTLSeconds,
	}, nil
}

// parseEchoResponse parses the `ip:port\0` response from the broker.
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

// sendNATKick fires a burst of empty UDP packets to the peer to open a
// local NAT mapping. The peer's kcp.Listener drops them (not valid KCP
// frames) but many routers open the outbound mapping after seeing the
// first few packets.
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

// HolePunch sends a burst of empty UDP packets from punchConn to
// peerIP:peerPort (a best-effort kick to open the local NAT mapping),
// then immediately returns a *kcp.UDPSession in client mode bound to the
// punch socket. The kamune handshake that follows drives the KCP SYN/ACK
// exchange — if the peer is unreachable, the handshake will fail with a
// transport-level error.
//
// The background burst is fire-and-forget: the listener's kcp.Listener
// drops non-KCP frames, so we don't wait for a reply. The burst is kept
// for NAT-tickling on routers that need a few outbound packets before
// creating a mapping.
//
// KCP parameters are 0/0 (no FEC) to match the kamune library's default
// DialWithUDP and ServeWithUDP.
func (b *BrokerClient) HolePunch(
	ctx context.Context, punchConn *net.UDPConn,
	peerIP net.IP, peerPort uint16, _ time.Duration,
) (*kcp.UDPSession, error) {
	peerAddr := &net.UDPAddr{IP: peerIP, Port: int(peerPort)}

	punchCtx, punchCancel := context.WithCancel(ctx)
	defer punchCancel()
	go sendNATKick(punchCtx, punchConn, peerAddr)

	// Create a kcp client session on the punch socket. The kamune
	// handshake's first Write triggers the KCP SYN; the listener's
	// kcp.ServeConn accepts it.
	var convid uint32
	binary.Read(rand.Reader, binary.LittleEndian, &convid)
	sess, err := kcp.NewConn4(convid, peerAddr, nil, 0, 0, true, punchConn)
	if err != nil {
		return nil, fmt.Errorf("kcp session: %w", err)
	}
	return sess, nil
}
