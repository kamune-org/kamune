package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/xtaci/kcp-go/v5"

	relaybroker "github.com/kamune-org/kamune/pkg/relayconn/broker"
)

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
	client, err := b.Client(brokerAddr)
	if err != nil {
		punchConn.Close()
		return nil, relaybroker.Payload{}, fmt.Errorf("broker client: %w", err)
	}

	// ECHO from the punch socket so the broker's view of our address is
	// the punch socket's external address:port (the address the broker
	// will send NOTIFYs to). EchoOn takes only the broker's reply.
	claimIP, claimPort, err := client.EchoOn(ctx, punchConn)
	if err != nil {
		punchConn.Close()
		return nil, relaybroker.Payload{}, fmt.Errorf("broker echo: %w", err)
	}

	// REGISTER from the punch socket. The broker stores the (token, our
	// X25519 pub, claimIP:claimPort) tuple and will match us with a peer
	// that registers with the same token.
	pkt := relaybroker.BuildRegister(
		token, client.PublicKey(), claimIP, claimPort,
	)
	if _, err := punchConn.WriteToUDP(pkt, brokerUDPAddr); err != nil {
		punchConn.Close()
		return nil, relaybroker.Payload{}, fmt.Errorf("send register: %w", err)
	}

	// Read NOTIFYs from the punch socket in a loop and return on the
	// first PEER_MATCHED. TOKEN_ASSIGNED is skipped: the caller
	// registers a token it already holds, the one the server shared or
	// the static one both peers derive, so it has no use for one the
	// broker assigns.
	buf := make([]byte, 1500)
	lastRegister := time.Now()
	for {
		select {
		case <-ctx.Done():
			punchConn.Close()
			return nil, relaybroker.Payload{}, ctx.Err()
		default:
		}
		if time.Since(lastRegister) >= 25*time.Second {
			_, _ = punchConn.WriteToUDP(pkt, brokerUDPAddr)
			lastRegister = time.Now()
		}
		if err := punchConn.SetReadDeadline(
			time.Now().Add(500 * time.Millisecond),
		); err != nil {
			punchConn.Close()
			return nil, relaybroker.Payload{}, fmt.Errorf("set read deadline: %w", err)
		}
		n, src, err := punchConn.ReadFromUDP(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			punchConn.Close()
			return nil, relaybroker.Payload{}, fmt.Errorf("read notify: %w", err)
		}
		if !src.IP.Equal(brokerUDPAddr.IP) || src.Port != brokerUDPAddr.Port {
			continue
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
			// the check. The broker echoes the 16-byte wire
			// form of the token, which never equals a 32-byte
			// static token byte for byte.
			if len(token) > 0 &&
				!relaybroker.TokenMatches(payload.Token, token) {
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

// HolePunch returns a *kcp.UDPSession in client mode bound to punchConn
// that talks to peerIP:peerPort, and sends a burst of NAT kicks to that
// address from punchConn in the background, to open the local NAT
// mapping for it on routers that need a few outbound packets first. The
// burst goes on after HolePunch returns, until it ends or ctx does.
//
// HolePunch does not wait for the peer: the kamune handshake that follows
// drives the KCP exchange, and fails with a transport-level error if the
// peer is unreachable. The listener's filter drops the kicks, which are
// too short for KCP.
//
// KCP parameters are 0/0 (no FEC) to match the kamune library's default
// DialWithUDP and ServeWithUDP.
func (b *BrokerClient) HolePunch(
	ctx context.Context, punchConn *net.UDPConn,
	peerIP net.IP, peerPort uint16,
) (*kcp.UDPSession, error) {
	peerAddr := &net.UDPAddr{IP: peerIP, Port: int(peerPort)}
	go sendNATKick(ctx, punchConn, peerAddr)

	// Create a kcp client session on the punch socket. The kamune
	// handshake's first Write sends the first KCP segment; the
	// listener's kcp.ServeConn accepts it.
	var convid uint32
	binary.Read(rand.Reader, binary.LittleEndian, &convid)
	sess, err := kcp.NewConn4(convid, peerAddr, nil, 0, 0, true, punchConn)
	if err != nil {
		return nil, fmt.Errorf("kcp session: %w", err)
	}
	return sess, nil
}
