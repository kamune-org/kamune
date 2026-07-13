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

var echoRequest = []byte{'K', 'B', 'R', 'K', 0x01, 0x01}

var ErrHolePunchFailed = errors.New("hole-punch failed")

const DefaultHolePunchTimeout = 5 * time.Second

type BrokerClient struct {
	key *ecdh.PrivateKey
	pub []byte

	mu         sync.Mutex
	client     *relaybroker.Client
	brokerAddr string
}

func NewBrokerClient() (*BrokerClient, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate x25519 key: %w", err)
	}
	return &BrokerClient{key: k, pub: k.PublicKey().Bytes()}, nil
}

func (b *BrokerClient) PublicKey() []byte {
	out := make([]byte, len(b.pub))
	copy(out, b.pub)
	return out
}

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
			if len(token) > 0 && !bytes.Equal(payload.Token, token) {
				continue
			}
			_ = punchConn.SetReadDeadline(time.Time{})
			return punchConn, *payload, nil
		}
	}
}

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
	peerIP net.IP, peerPort uint16, _ time.Duration,
) (*kcp.UDPSession, error) {
	peerAddr := &net.UDPAddr{IP: peerIP, Port: int(peerPort)}

	punchCtx, punchCancel := context.WithCancel(ctx)
	defer punchCancel()
	go sendNATKick(punchCtx, punchConn, peerAddr)

	var convid uint32
	binary.Read(rand.Reader, binary.LittleEndian, &convid)
	sess, err := kcp.NewConn4(convid, peerAddr, nil, 0, 0, true, punchConn)
	if err != nil {
		return nil, fmt.Errorf("kcp session: %w", err)
	}
	return sess, nil
}
