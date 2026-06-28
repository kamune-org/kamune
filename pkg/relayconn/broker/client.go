package broker

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

// DefaultEchoTimeout is the timeout for a single Echo request.
const DefaultEchoTimeout = 2 * time.Second

// DefaultRegisterTimeout is the timeout for a single Register request (the
// broker responds with NOTIFY(TOKEN_ASSIGNED) for random mode; static mode gets
// no response and the call returns immediately after the write).
const DefaultRegisterTimeout = 2 * time.Second

// Payload is the decoded plaintext of a NOTIFY packet — what the peer needs to
// act on.
type Payload struct {
	Type            NotifyType
	Token           []byte
	OtherPeerEphPub []byte // empty for TOKEN_ASSIGNED
	IP              net.IP // zero for TOKEN_ASSIGNED
	Port            uint16 // zero for TOKEN_ASSIGNED
	TTLSeconds      uint32 // only for TOKEN_ASSIGNED
}

// Client is the peer-side API for the kamune broker. The same instance is used
// for Echo, Register, and Listen. The client's ephemeral X25519 key is stable
// across calls so the broker can identify the same peer for self-match.
type Client struct {
	relayAddr *net.UDPAddr
	key       *ecdh.PrivateKey
	pub       []byte
}

// NewClient returns a Client that talks to the broker at the given address. The
// client generates a fresh ephemeral X25519 key on construction; reuse the same
// Client for the lifetime of the peer process so re-registrations keep the same
// identity.
func NewClient(relayAddr string) (*Client, error) {
	addr, err := net.ResolveUDPAddr("udp4", relayAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve broker addr %q: %w", relayAddr, err)
	}
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate x25519 key: %w", err)
	}
	return &Client{
		relayAddr: addr,
		key:       k,
		pub:       k.PublicKey().Bytes(),
	}, nil
}

// PublicKey returns the client's 32-byte X25519 public key. Useful for tests
// and for logging.
func (c *Client) PublicKey() []byte {
	out := make([]byte, len(c.pub))
	copy(out, c.pub)
	return out
}

// Echo sends a STUN_ECHO to the broker and returns the perceived public IP:port.
// The context is honored for the request and the 2s read deadline. Errors
// include a deadline-exceeded if the broker doesn't respond in time.
func (c *Client) Echo(ctx context.Context) (net.IP, uint16, error) {
	conn, err := net.DialUDP("udp4", nil, c.relayAddr)
	if err != nil {
		return nil, 0, fmt.Errorf("dial broker: %w", err)
	}
	defer conn.Close()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(DefaultEchoTimeout)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, 0, fmt.Errorf("set deadline: %w", err)
	}

	pkt := buildEchoRequest()
	if _, err := conn.Write(pkt); err != nil {
		return nil, 0, fmt.Errorf("write echo: %w", err)
	}

	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, 0, fmt.Errorf("read echo response: %w", err)
	}
	return parseEchoResponse(buf[:n])
}

// Register sends a REGISTER to the broker and returns the assigned token. For
// random mode (token == nil), the broker responds with NOTIFY(TOKEN_ASSIGNED);
// the returned token is the new random token. For static mode (token != nil),
// the broker stores the registration and sends no NOTIFY; the returned token is
// the same as the input.
//
// claimIP and claimPort are the peer's perceived public address (use Echo to
// discover it). They are written into the REGISTER so the broker can echo them
// back to a matched peer.
func (c *Client) Register(
	ctx context.Context, token []byte, claimIP net.IP, claimPort uint16,
) ([]byte, error) {
	conn, err := net.DialUDP("udp4", nil, c.relayAddr)
	if err != nil {
		return nil, fmt.Errorf("dial broker: %w", err)
	}
	defer conn.Close()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(DefaultRegisterTimeout)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("set deadline: %w", err)
	}

	pkt := BuildRegister(token, c.pub, claimIP, claimPort)
	if _, err := conn.Write(pkt); err != nil {
		return nil, fmt.Errorf("write register: %w", err)
	}

	// Static mode: no response expected. The broker holds the registration; the
	// matching peer will trigger a NOTIFY later (delivered via Listen). Treat
	// any incoming packet as the response and parse it; if it's empty, treat as
	// success.
	if len(token) != 0 {
		// Best-effort: drain a single packet with a short timeout so we don't
		// hang if the broker sends nothing (which it won't for static mode).
		// Return the input token.
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		buf := make([]byte, 1500)
		if _, err := conn.Read(buf); err == nil {
			// Broker unexpectedly sent something; parse and return the token
			// from the response.
			return c.decodeAssignedToken(buf)
		}
		return token, nil
	}

	// Random mode: wait for NOTIFY(TOKEN_ASSIGNED).
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read register response: %w", err)
	}
	return c.decodeAssignedToken(buf[:n])
}

// Listen opens a UDP socket and returns a channel of decoded NOTIFY payloads.
// The channel is closed when ctx is cancelled or the underlying socket errors.
// The peer's local address (where the broker sends NOTIFYs to) is returned so
// the caller can pass it to the broker via Register.
//
// The client must be running for the broker to deliver a match NOTIFY. Call
// Register first to let the broker know the peer's claimIP:claimPort.
func (c *Client) Listen(ctx context.Context) (
	<-chan Payload, *net.UDPAddr, error,
) {
	addr, err := net.ResolveUDPAddr("udp4", "127.0.0.1:0")
	if err != nil {
		return nil, nil, fmt.Errorf("resolve local addr: %w", err)
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen udp: %w", err)
	}

	out := make(chan Payload, 1)

	go func() {
		defer close(out)
		defer conn.Close()

		buf := make([]byte, 1500)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					continue
				}
				// Socket closed (ctx cancelled → caller called Close, or
				// external close). Exit.
				return
			}
			payload, err := c.decodeNotify(buf[:n])
			if err != nil {
				continue
			}
			select {
			case out <- *payload:
			case <-ctx.Done():
				return
			}
		}
	}()

	return out, conn.LocalAddr().(*net.UDPAddr), nil
}

// decodeAssignedToken parses a NOTIFY(TOKEN_ASSIGNED) response and returns the
// assigned token.
func (c *Client) decodeAssignedToken(pkt []byte) ([]byte, error) {
	plaintext, err := c.openNotify(pkt)
	if err != nil {
		return nil, err
	}
	payload, err := ParseNotifyPayload(plaintext)
	if err != nil {
		return nil, err
	}
	if payload.Type != NotifyTokenAssigned {
		return nil, fmt.Errorf("expected TOKEN_ASSIGNED, got %v", payload.Type)
	}
	return payload.Token, nil
}

// decodeNotify parses a NOTIFY and returns its payload. Used by Listen.
func (c *Client) decodeNotify(pkt []byte) (*Payload, error) {
	plaintext, err := c.openNotify(pkt)
	if err != nil {
		return nil, err
	}
	payload, err := ParseNotifyPayload(plaintext)
	if err != nil {
		return nil, err
	}
	out := Payload{
		Type:            payload.Type,
		Token:           append([]byte(nil), payload.Token...),
		OtherPeerEphPub: append([]byte(nil), payload.OtherPeerEphPub...),
		IP:              append(net.IP(nil), payload.IP...),
		Port:            payload.Port,
		TTLSeconds:      payload.TTLSeconds,
	}
	return &out, nil
}

// openNotify decrypts a NOTIFY packet using the client's private key and the
// broker's ephemeral public key from the header.
func (c *Client) openNotify(pkt []byte) ([]byte, error) {
	brokerEphPub, nonce, sealed, err := ParseNotify(pkt)
	if err != nil {
		return nil, fmt.Errorf("parse notify: %w", err)
	}
	brokerPub, err := ecdh.X25519().NewPublicKey(brokerEphPub)
	if err != nil {
		return nil, fmt.Errorf("parse broker eph pub: %w", err)
	}
	shared, err := c.key.ECDH(brokerPub)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}
	key := sha256.Sum256(shared)
	return OpenNotify(key[:], brokerEphPub, nonce, sealed)
}

// buildEchoRequest builds a 6-byte STUN_ECHO packet.
func buildEchoRequest() []byte {
	return []byte{'K', 'B', 'R', 'K', 0x01, 0x01}
}

// parseEchoResponse parses the `ip:port\0` response from the broker.
func parseEchoResponse(resp []byte) (net.IP, uint16, error) {
	// Response is "ip:port\0" (null-terminated).
	end := bytes.IndexByte(resp, 0)
	if end < 0 {
		end = len(resp)
	}
	s := string(resp[:end])
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return nil, 0, fmt.Errorf("malformed echo response %q: %w", s, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 0, fmt.Errorf("parse ip %q: invalid", host)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, 0, fmt.Errorf("parse port %q: %w", portStr, err)
	}
	return ip, uint16(port), nil
}
