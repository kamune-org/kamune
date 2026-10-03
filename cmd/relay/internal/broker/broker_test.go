package broker

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/cmd/relay/internal/config"
	relaybroker "github.com/kamune-org/kamune/pkg/relayconn/broker"
)

// newTestBroker binds a real UDP socket on 127.0.0.1:0 (kernel-assigned port)
// and starts the Run loop in a goroutine. The cleanup function closes the
// broker socket.
func newTestBroker(t *testing.T, ttl time.Duration) *Broker {
	t.Helper()
	a := require.New(t)
	cfg := config.Broker{
		Enabled:         true,
		Address:         "127.0.0.1:0",
		RegistrationTTL: ttl,
	}
	b, err := New(cfg, nil)
	a.NoError(err)

	go b.Run(context.Background())

	t.Cleanup(func() { _ = b.Close() })
	return b
}

func TestRun_CloseIsCleanShutdown(t *testing.T) {
	a := require.New(t)
	b, err := New(config.Broker{
		Enabled: true,
		Address: "127.0.0.1:0",
	}, nil)
	a.NoError(err)

	runErr := make(chan error, 1)
	go func() {
		runErr <- b.Run(context.Background())
	}()

	a.NoError(b.Close())
	select {
	case err := <-runErr:
		a.NoError(err)
	case <-time.After(time.Second):
		a.FailNow("broker Run did not return after Close")
	}
}

// faultyConn returns the queued errors from ReadFromUDP and SetReadDeadline,
// one per call, before it uses the real socket again.
type faultyConn struct {
	*net.UDPConn
	errs         []error
	deadlineErrs []error
	mu           sync.Mutex
}

func (c *faultyConn) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) {
	c.mu.Lock()
	if len(c.errs) > 0 {
		err := c.errs[0]
		c.errs = c.errs[1:]
		c.mu.Unlock()
		return 0, nil, err
	}
	c.mu.Unlock()
	return c.UDPConn.ReadFromUDP(b)
}

func (c *faultyConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	if len(c.deadlineErrs) > 0 {
		err := c.deadlineErrs[0]
		c.deadlineErrs = c.deadlineErrs[1:]
		c.mu.Unlock()
		return err
	}
	c.mu.Unlock()
	return c.UDPConn.SetReadDeadline(t)
}

// failingConn fails every read and counts the attempts.
type failingConn struct {
	*net.UDPConn
	reads atomic.Int64
}

func (c *failingConn) ReadFromUDP([]byte) (int, *net.UDPAddr, error) {
	c.reads.Add(1)
	return 0, nil, errors.New("persistent read failure")
}

func TestRun_SurvivesPacketReadErrors(t *testing.T) {
	// wsaEMSGSIZE is what Windows returns for a datagram larger than the
	// read buffer.
	const wsaEMSGSIZE = syscall.Errno(10040)
	tests := []struct {
		name         string
		errs         []error
		deadlineErrs []error
	}{
		{
			name: "message too long",
			errs: []error{&net.OpError{
				Op:  "read",
				Net: "udp",
				Err: os.NewSyscallError("wsarecvfrom", wsaEMSGSIZE),
			}},
		},
		{
			name: "unknown error",
			errs: []error{errors.New("transient read failure")},
		},
		{
			name: "burst of errors",
			errs: func() []error {
				errs := make([]error, readErrBurst+2)
				for i := range errs {
					errs[i] = errors.New("transient read failure")
				}
				return errs
			}(),
		},
		{
			name:         "set read deadline error",
			deadlineErrs: []error{errors.New("transient deadline failure")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			b, err := New(config.Broker{
				Enabled: true,
				Address: "127.0.0.1:0",
			}, nil)
			a.NoError(err)
			udp, ok := b.conn.(*net.UDPConn)
			a.True(ok)
			b.conn = &faultyConn{
				UDPConn:      udp,
				errs:         tt.errs,
				deadlineErrs: tt.deadlineErrs,
			}

			runErr := make(chan error, 1)
			go func() { runErr <- b.Run(context.Background()) }()
			t.Cleanup(func() { _ = b.Close() })

			client := newTestClient(t)
			pkt := []byte{'K', 'B', 'R', 'K', 0x01, 0x01}
			resp := sendAndRead(t, client, b.Addr(), pkt)
			a.NotEmpty(resp, "broker must keep serving after a read error")

			select {
			case err := <-runErr:
				a.FailNow("Run returned after a read error", "%v", err)
			default:
			}
		})
	}
}

func TestRun_SurvivesOversizedDatagram(t *testing.T) {
	// maxIPv4UDPPayload is the largest datagram IPv4 can carry. The read
	// buffer must hold it, or Windows fails the read with WSAEMSGSIZE.
	const maxIPv4UDPPayload = 65507
	a := require.New(t)
	a.GreaterOrEqual(readBufSize, maxIPv4UDPPayload)
	b := newTestBroker(t, time.Minute)
	client := newTestClient(t)

	// Larger than an Ethernet MTU. No valid header, so the only response
	// the client sees is to the echo that follows.
	for _, size := range []int{4000, maxIPv4UDPPayload} {
		_, err := client.WriteToUDP(make([]byte, size), b.Addr())
		a.NoError(err)
	}

	pkt := []byte{'K', 'B', 'R', 'K', 0x01, 0x01}
	resp := sendAndRead(t, client, b.Addr(), pkt)
	a.NotEmpty(resp)
}

func TestRun_BacksOffOnPersistentReadErrors(t *testing.T) {
	a := require.New(t)
	b, err := New(config.Broker{
		Enabled: true,
		Address: "127.0.0.1:0",
	}, nil)
	a.NoError(err)
	udp, ok := b.conn.(*net.UDPConn)
	a.True(ok)
	conn := &failingConn{UDPConn: udp}
	b.conn = conn
	t.Cleanup(func() { _ = b.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	start := time.Now()
	go func() { runErr <- b.Run(ctx) }()

	// Run must keep reading after the burst: wait for two backoff reads.
	a.Eventually(func() bool {
		return conn.reads.Load() >= int64(readErrBurst)+2
	}, 10*time.Second, 10*time.Millisecond, "Run must keep reading")
	cancel()
	select {
	case err := <-runErr:
		a.NoError(err)
	case <-time.After(10 * time.Second):
		a.FailNow("Run did not return after cancel")
	}
	// Measured after Run returned, so a late wake-up on a loaded runner
	// raises the bound by the backoff reads it allowed.
	elapsed := time.Since(start)

	// readErrBurst reads fail at full speed, then Run waits readErrBackoff
	// before each read. A loop that spins makes millions of reads.
	maxReads := int64(readErrBurst) + int64(elapsed/readErrBackoff) + 2
	a.LessOrEqual(conn.reads.Load(), maxReads)
}

// newTestClient returns a UDP socket bound to 127.0.0.1:0, suitable for sending
// packets to the broker and reading the response.
func newTestClient(t *testing.T) *net.UDPConn {
	t.Helper()
	a := require.New(t)
	addr, err := net.ResolveUDPAddr("udp4", "127.0.0.1:0")
	a.NoError(err)
	c, err := net.ListenUDP("udp4", addr)
	a.NoError(err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// peerKey generates a fresh X25519 key pair and returns the private key (for
// ECDH) and the public key bytes (for REGISTER).
func peerKey(t *testing.T) (*ecdh.PrivateKey, []byte) {
	t.Helper()
	a := require.New(t)
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	a.NoError(err)
	return k, k.PublicKey().Bytes()
}

// sendAndRead sends pkt to the broker and reads a single response with a
// 2-second deadline.
func sendAndRead(t *testing.T, c *net.UDPConn, brokerAddr *net.UDPAddr, pkt []byte) []byte {
	t.Helper()
	a := require.New(t)
	_, err := c.WriteToUDP(pkt, brokerAddr)
	a.NoError(err)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := c.ReadFromUDP(buf)
	a.NoError(err, "expected response within 2s")
	return buf[:n]
}

// decryptNotify peeks at the broker's ephemeral public key in the NOTIFY
// header, derives the shared secret with the peer's private key, and opens the
// AEAD ciphertext.
func decryptNotify(
	t *testing.T, peerPriv *ecdh.PrivateKey, pkt []byte,
) (relaybroker.NotifyPayload, error) {
	t.Helper()
	a := require.New(t)
	brokerEphPub, nonce, sealed, err := relaybroker.ParseNotify(pkt)
	a.NoError(err)

	brokerPub, err := ecdh.X25519().NewPublicKey(brokerEphPub)
	a.NoError(err)
	shared, err := peerPriv.ECDH(brokerPub)
	a.NoError(err)
	key := sha256.Sum256(shared)

	plaintext, err := relaybroker.OpenNotify(key[:], brokerEphPub, nonce, sealed)
	a.NoError(err)
	return relaybroker.ParseNotifyPayload(plaintext)
}

func TestSTUNEcho_RespondsWithSenderIP(t *testing.T) {
	a := require.New(t)
	b := newTestBroker(t, time.Minute)
	client := newTestClient(t)

	pkt := []byte{'K', 'B', 'R', 'K', 0x01, 0x01}
	resp := sendAndRead(t, client, b.Addr(), pkt)

	// Response is "ip:port\0". The client source is 127.0.0.1.
	srcAddr := client.LocalAddr().(*net.UDPAddr)
	ip4 := srcAddr.IP.To4()
	a.NotNil(ip4, "client source must be IPv4")
	expected := fmt.Sprintf("%s:%d\x00", ip4.String(), srcAddr.Port)
	a.Equal(expected, string(resp))
}

func TestSTUNEcho_IgnoresUnknownMagic(t *testing.T) {
	a := require.New(t)
	b := newTestBroker(t, time.Minute)
	client := newTestClient(t)

	pkt := []byte{'D', 'E', 'A', 'D', 0x00, 0x01, 0x01}
	_, err := client.WriteToUDP(pkt, b.Addr())
	a.NoError(err)
	_ = client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1500)
	_, _, err = client.ReadFromUDP(buf)
	a.Error(err, "expected read timeout (no response)")
}

func TestSTUNEcho_IgnoresUnknownOpcode(t *testing.T) {
	a := require.New(t)
	b := newTestBroker(t, time.Minute)
	client := newTestClient(t)

	pkt := []byte{'K', 'B', 'R', 'K', 0x01, 0xFF} // unknown opcode
	_, err := client.WriteToUDP(pkt, b.Addr())
	a.NoError(err)
	_ = client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1500)
	_, _, err = client.ReadFromUDP(buf)
	a.Error(err, "expected read timeout (no response)")
}

func TestSTUNEcho_IgnoresUnknownVersion(t *testing.T) {
	a := require.New(t)
	b := newTestBroker(t, time.Minute)
	client := newTestClient(t)

	pkt := []byte{'K', 'B', 'R', 'K', 0x02, 0x01} // VER=2
	_, err := client.WriteToUDP(pkt, b.Addr())
	a.NoError(err)
	_ = client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1500)
	_, _, err = client.ReadFromUDP(buf)
	a.Error(err, "expected read timeout (no response)")
}

func TestSTUNEcho_IgnoresShortPacket(t *testing.T) {
	a := require.New(t)
	b := newTestBroker(t, time.Minute)
	client := newTestClient(t)

	pkt := []byte{'K', 'B', 'R', 'K'} // 4 bytes, no VER/OPCODE
	_, err := client.WriteToUDP(pkt, b.Addr())
	a.NoError(err)
	_ = client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1500)
	_, _, err = client.ReadFromUDP(buf)
	a.Error(err, "expected read timeout (no response)")
}

func TestSTUNEcho_ContentIgnored(t *testing.T) {
	a := require.New(t)
	b := newTestBroker(t, time.Minute)
	client := newTestClient(t)

	// 6-byte STUN_ECHO + 100 trailing bytes — response is based on
	// source address, not packet content.
	pkt := append(
		[]byte{'K', 'B', 'R', 'K', 0x01, 0x01},
		make([]byte, 100)...,
	)
	resp := sendAndRead(t, client, b.Addr(), pkt)

	srcAddr := client.LocalAddr().(*net.UDPAddr)
	ip4 := srcAddr.IP.To4()
	a.NotNil(ip4)
	expected := fmt.Sprintf("%s:%d\x00", ip4.String(), srcAddr.Port)
	a.Equal(expected, string(resp))
}

func TestRegister_Random_AssignsToken(t *testing.T) {
	a := require.New(t)
	b := newTestBroker(t, time.Minute)
	client := newTestClient(t)
	priv, pub := peerKey(t)

	// Empty token = random mode.
	clientAddr := client.LocalAddr().(*net.UDPAddr)
	ip4 := clientAddr.IP.To4()
	a.NotNil(ip4)
	pkt := relaybroker.BuildRegister(nil, pub, ip4, uint16(clientAddr.Port))
	resp := sendAndRead(t, client, b.Addr(), pkt)

	payload, err := decryptNotify(t, priv, resp)
	a.NoError(err)
	a.Equal(relaybroker.NotifyTokenAssigned, payload.Type)
	a.Len(payload.Token, 16, "assigned token must be 16 bytes")
	a.NotZero(payload.TTLSeconds, "TTL must be > 0")
}

func TestRegister_Random_AssignedTokenStored(t *testing.T) {
	a := require.New(t)
	b := newTestBroker(t, time.Minute)
	peer1Client := newTestClient(t)
	peer1Priv, peer1Pub := peerKey(t)
	peer2Client := newTestClient(t)
	peer2Priv, peer2Pub := peerKey(t)

	// Peer 1: random mode, get an assigned token.
	peer1Addr := peer1Client.LocalAddr().(*net.UDPAddr)
	peer1IP4 := peer1Addr.IP.To4()
	a.NotNil(peer1IP4)
	pkt1 := relaybroker.BuildRegister(
		nil, peer1Pub, peer1IP4, uint16(peer1Addr.Port),
	)
	resp1 := sendAndRead(t, peer1Client, b.Addr(), pkt1)
	assigned, err := decryptNotify(t, peer1Priv, resp1)
	a.NoError(err)
	a.Equal(relaybroker.NotifyTokenAssigned, assigned.Type)
	token := assigned.Token

	// Peer 2: join with the assigned token.
	peer2IP4 := peer2Client.LocalAddr().(*net.UDPAddr).IP.To4()
	a.NotNil(peer2IP4)
	pkt2 := relaybroker.BuildRegister(
		token,
		peer2Pub,
		peer2IP4,
		uint16(peer2Client.LocalAddr().(*net.UDPAddr).Port),
	)
	resp2 := sendAndRead(t, peer2Client, b.Addr(), pkt2)
	peer2Payload, err := decryptNotify(t, peer2Priv, resp2)
	a.NoError(err)
	a.Equal(relaybroker.NotifyPeerMatched, peer2Payload.Type)
	// Peer 2 should see peer 1's IP:port + eph pub.
	a.Equal(peer1Pub, peer2Payload.OtherPeerEphPub)
	a.Equal(peer1IP4, net.IP(peer2Payload.IP))
	a.Equal(uint16(peer1Addr.Port), peer2Payload.Port)

	// Peer 1 should also receive a NOTIFY(PEER_MATCHED). Send a
	// STUN_ECHO to ensure the broker is still alive, then read on
	// peer1Client — the NOTIFY should be queued.
	go func() {
		// Trigger a read deadline on peer1Client by sending a
		// STUN_ECHO first; the response unblocks the read briefly.
		// Simpler: just wait then read.
		time.Sleep(50 * time.Millisecond)
	}()
	_ = peer1Client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := peer1Client.ReadFromUDP(buf)
	a.NoError(err)
	peer1Payload, err := decryptNotify(t, peer1Priv, buf[:n])
	a.NoError(err)
	a.Equal(relaybroker.NotifyPeerMatched, peer1Payload.Type)
	a.Equal(peer2Pub, peer1Payload.OtherPeerEphPub)
}

func TestRegister_Static_HoldsUntilMatch(t *testing.T) {
	a := require.New(t)
	b := newTestBroker(t, time.Minute)
	client := newTestClient(t)
	_, pub := peerKey(t)

	// Static token, no second peer — no NOTIFY.
	token := make([]byte, 16)
	for i := range token {
		token[i] = byte(i + 1)
	}
	ip4 := client.LocalAddr().(*net.UDPAddr).IP.To4()
	pkt := relaybroker.BuildRegister(
		token,
		pub,
		ip4,
		uint16(client.LocalAddr().(*net.UDPAddr).Port),
	)
	_, err := client.WriteToUDP(pkt, b.Addr())
	a.NoError(err)

	_ = client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1500)
	_, _, err = client.ReadFromUDP(buf)
	a.Error(err, "expected read timeout (no NOTIFY on hold)")
}

func TestRegister_Static_MatchNotifiesBoth(t *testing.T) {
	a := require.New(t)
	b := newTestBroker(t, time.Minute)
	peer1Client := newTestClient(t)
	peer1Priv, peer1Pub := peerKey(t)
	peer2Client := newTestClient(t)
	peer2Priv, peer2Pub := peerKey(t)

	token := make([]byte, 16)
	for i := range token {
		token[i] = byte(i + 1)
	}

	peer1IP4 := peer1Client.LocalAddr().(*net.UDPAddr).IP.To4()
	pkt1 := relaybroker.BuildRegister(
		token,
		peer1Pub,
		peer1IP4,
		uint16(peer1Client.LocalAddr().(*net.UDPAddr).Port),
	)
	_, err := peer1Client.WriteToUDP(pkt1, b.Addr())
	a.NoError(err)

	// Small delay so peer 1's hold is registered before peer 2 joins.
	time.Sleep(20 * time.Millisecond)

	peer2IP4 := peer2Client.LocalAddr().(*net.UDPAddr).IP.To4()
	pkt2 := relaybroker.BuildRegister(
		token,
		peer2Pub,
		peer2IP4,
		uint16(peer2Client.LocalAddr().(*net.UDPAddr).Port),
	)
	resp2 := sendAndRead(t, peer2Client, b.Addr(), pkt2)
	peer2Payload, err := decryptNotify(t, peer2Priv, resp2)
	a.NoError(err)
	a.Equal(relaybroker.NotifyPeerMatched, peer2Payload.Type)

	// Read peer 1's NOTIFY.
	_ = peer1Client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := peer1Client.ReadFromUDP(buf)
	a.NoError(err)
	peer1Payload, err := decryptNotify(t, peer1Priv, buf[:n])
	a.NoError(err)
	a.Equal(relaybroker.NotifyPeerMatched, peer1Payload.Type)

	// Each NOTIFY must use a different broker ephemeral public key
	// (forward secrecy per NOTIFY).
	peer1NotifyBrokerEph := peer1Payload.OtherPeerEphPub // not the broker key — placeholder
	_ = peer1NotifyBrokerEph
}

func TestRegister_ReRegistration_RefreshesTTL(t *testing.T) {
	a := require.New(t)
	b := newTestBroker(t, 200*time.Millisecond)
	client := newTestClient(t)
	_, pub := peerKey(t)

	token := make([]byte, 16)
	for i := range token {
		token[i] = byte(i + 1)
	}
	ip4 := client.LocalAddr().(*net.UDPAddr).IP.To4()
	pkt := relaybroker.BuildRegister(token, pub, ip4, uint16(client.LocalAddr().(*net.UDPAddr).Port))

	_, err := client.WriteToUDP(pkt, b.Addr())
	a.NoError(err)
	// Wait 100ms (half of TTL).
	time.Sleep(100 * time.Millisecond)
	// Re-register — same source + same key → refresh TTL.
	_, err = client.WriteToUDP(pkt, b.Addr())
	a.NoError(err)
	// Wait another 150ms — past the original TTL, but within the
	// refreshed TTL. The entry should still be in the registry.
	time.Sleep(150 * time.Millisecond)

	// A second peer joining with the same token triggers a match
	// (verifying the first peer's entry wasn't evicted).
	peer2Client := newTestClient(t)
	_, peer2Pub := peerKey(t)
	pkt2 := relaybroker.BuildRegister(
		token,
		peer2Pub,
		peer2Client.LocalAddr().(*net.UDPAddr).IP.To4(),
		uint16(peer2Client.LocalAddr().(*net.UDPAddr).Port),
	)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = peer2Client.WriteToUDP(pkt2, b.Addr())
	a.NoError(err)
	buf := make([]byte, 1500)
	n, _, err := client.ReadFromUDP(buf)
	a.NoError(err, "entry should still be alive after refresh")
	a.Greater(n, 0, "received non-empty response")
}

func TestRegister_SelfMatch_NotBlocked(t *testing.T) {
	// Self-match: same source re-registers with the same token →
	// refresh TTL, no NOTIFY.
	a := require.New(t)
	b := newTestBroker(t, time.Minute)
	client := newTestClient(t)
	_, pub := peerKey(t)

	token := make([]byte, 16)
	for i := range token {
		token[i] = byte(i + 1)
	}
	ip4 := client.LocalAddr().(*net.UDPAddr).IP.To4()
	pkt := relaybroker.BuildRegister(
		token,
		pub,
		ip4,
		uint16(client.LocalAddr().(*net.UDPAddr).Port),
	)

	_, err := client.WriteToUDP(pkt, b.Addr())
	a.NoError(err)
	// Re-register with the same source and same eph key.
	_, err = client.WriteToUDP(pkt, b.Addr())
	a.NoError(err)

	_ = client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1500)
	_, _, err = client.ReadFromUDP(buf)
	a.Error(err, "self-match should not produce a NOTIFY")
}

func TestRegister_EmptyIP_Ignored(t *testing.T) {
	a := require.New(t)
	b := newTestBroker(t, time.Minute)
	client := newTestClient(t)
	_, pub := peerKey(t)

	// Zero IP — REGISTER is rejected.
	pkt := relaybroker.BuildRegister(nil, pub, net.IPv4(0, 0, 0, 0), 12345)
	_, err := client.WriteToUDP(pkt, b.Addr())
	a.NoError(err)
	_ = client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1500)
	_, _, err = client.ReadFromUDP(buf)
	a.Error(err, "expected read timeout (empty IP rejected)")
}

func TestRegister_EmptyPeerEphPub_Ignored(t *testing.T) {
	a := require.New(t)
	b := newTestBroker(t, time.Minute)
	client := newTestClient(t)

	// All-zero peer eph pub.
	zeroPub := make([]byte, 32)
	ip4 := client.LocalAddr().(*net.UDPAddr).IP.To4()
	pkt := relaybroker.BuildRegister(
		nil,
		zeroPub,
		ip4,
		uint16(client.LocalAddr().(*net.UDPAddr).Port),
	)
	_, err := client.WriteToUDP(pkt, b.Addr())
	a.NoError(err)
	_ = client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1500)
	_, _, err = client.ReadFromUDP(buf)
	a.Error(err, "expected read timeout (zero pub rejected)")
}

func TestRegister_TTLExpires(t *testing.T) {
	a := require.New(t)
	// Use injectable clock to avoid real time wait.
	now := time.Unix(0, 0)
	b := &Broker{
		registry: make(map[string]*registration),
		ttl:      100 * time.Millisecond,
		now:      func() time.Time { return now },
	}
	b.mu.Lock()
	b.registry["token"] = &registration{
		addr:       &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234},
		peerEphPub: [32]byte{1},
		expires:    now.Add(b.ttl),
	}
	b.mu.Unlock()

	// Just before expiry — still present.
	now = now.Add(50 * time.Millisecond)
	b.purgeExpired()
	b.mu.Lock()
	a.Equal(1, len(b.registry))
	b.mu.Unlock()

	// Just after expiry — evicted.
	now = now.Add(60 * time.Millisecond)
	b.purgeExpired()
	b.mu.Lock()
	a.Equal(0, len(b.registry))
	b.mu.Unlock()
}

func TestRegister_NotifyIgnored(t *testing.T) {
	a := require.New(t)
	b := newTestBroker(t, time.Minute)
	client := newTestClient(t)

	// Peer sends NOTIFY — broker ignores it.
	pkt := []byte{'K', 'B', 'R', 'K', 0x01, 0x03}
	pkt = append(pkt, make([]byte, 100)...) // trailing junk
	_, err := client.WriteToUDP(pkt, b.Addr())
	a.NoError(err)
	_ = client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1500)
	_, _, err = client.ReadFromUDP(buf)
	a.Error(err, "expected read timeout (peer NOTIFY ignored)")
}

func TestSTUNEcho_RespectsRateLimit(t *testing.T) {
	// Tight quota = 2 per IP, then drop.
	count := 0
	var countMu sync.Mutex
	allow := func(key string) bool {
		countMu.Lock()
		defer countMu.Unlock()
		count++
		return count <= 2
	}
	a := require.New(t)
	cfg := config.Broker{
		Enabled:         true,
		Address:         "127.0.0.1:0",
		RegistrationTTL: time.Minute,
	}
	b, err := New(cfg, allow)
	a.NoError(err)
	go b.Run(context.Background())
	t.Cleanup(func() { _ = b.Close() })

	client := newTestClient(t)
	pkt := []byte{'K', 'B', 'R', 'K', 0x01, 0x01}

	// First two: response.
	_ = sendAndRead(t, client, b.Addr(), pkt)
	_ = sendAndRead(t, client, b.Addr(), pkt)

	// Third: dropped.
	_, err = client.WriteToUDP(pkt, b.Addr())
	a.NoError(err)
	_ = client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1500)
	_, _, err = client.ReadFromUDP(buf)
	a.Error(err, "expected read timeout (rate-limited)")
}

func TestNotify_DecryptFailsWithWrongKey(t *testing.T) {
	a := require.New(t)
	b := newTestBroker(t, time.Minute)
	client := newTestClient(t)
	_, pub := peerKey(t)

	clientAddr := client.LocalAddr().(*net.UDPAddr)
	ip4 := clientAddr.IP.To4()
	a.NotNil(ip4)
	pkt := relaybroker.BuildRegister(nil, pub, ip4, uint16(clientAddr.Port))
	resp := sendAndRead(t, client, b.Addr(), pkt)

	// Attempt to decrypt with a DIFFERENT peer's private key.
	wrongPriv, _ := peerKey(t)
	brokerEphPub, nonce, sealed, err := relaybroker.ParseNotify(resp)
	a.NoError(err)
	wrongPub, err := ecdh.X25519().NewPublicKey(brokerEphPub)
	a.NoError(err)
	wrongShared, err := wrongPriv.ECDH(wrongPub)
	a.NoError(err)
	wrongKey := sha256.Sum256(wrongShared)
	_, err = relaybroker.OpenNotify(wrongKey[:], brokerEphPub, nonce, sealed)
	a.Error(err, "decryption with wrong key must fail")
}

func TestNotify_AADBoundToBrokerKey(t *testing.T) {
	a := require.New(t)
	b := newTestBroker(t, time.Minute)
	client := newTestClient(t)
	priv, pub := peerKey(t)

	clientAddr := client.LocalAddr().(*net.UDPAddr)
	ip4 := clientAddr.IP.To4()
	a.NotNil(ip4)
	pkt := relaybroker.BuildRegister(nil, pub, ip4, uint16(clientAddr.Port))
	resp := sendAndRead(t, client, b.Addr(), pkt)

	// Capture the broker's eph pub and the rest of the packet.
	brokerEphPub, nonce, sealed, err := relaybroker.ParseNotify(resp)
	a.NoError(err)
	// Flip a bit in the broker eph pub.
	tampered := make([]byte, len(brokerEphPub))
	copy(tampered, brokerEphPub)
	tampered[0] ^= 0xFF

	// Recompute the AEAD key (same as the legit peer would) and try
	// to open with the TAMPERED eph pub in the AAD.
	legitPub, err := ecdh.X25519().NewPublicKey(brokerEphPub)
	a.NoError(err)
	shared, err := priv.ECDH(legitPub)
	a.NoError(err)
	key := sha256.Sum256(shared)
	_, err = relaybroker.OpenNotify(key[:], tampered, nonce, sealed)
	a.Error(err, "decryption with tampered AAD must fail")
}

func TestNotify_ForwardSecrecy(t *testing.T) {
	// Two NOTIFYs from the same session: each uses a fresh broker
	// ephemeral key, so deriving one shared secret doesn't help
	// derive the other.
	a := require.New(t)
	b := newTestBroker(t, time.Minute)
	peer1Client := newTestClient(t)
	peer1Priv, peer1Pub := peerKey(t)
	peer2Client := newTestClient(t)
	peer2Priv, peer2Pub := peerKey(t)

	// Peer 1: random mode → NOTIFY #1 (TOKEN_ASSIGNED).
	peer1Addr := peer1Client.LocalAddr().(*net.UDPAddr)
	peer1IP4 := peer1Addr.IP.To4()
	a.NotNil(peer1IP4)
	pkt1 := relaybroker.BuildRegister(
		nil, peer1Pub, peer1IP4, uint16(peer1Addr.Port),
	)
	resp1 := sendAndRead(t, peer1Client, b.Addr(), pkt1)
	brokerEph1, _, _, err := relaybroker.ParseNotify(resp1)
	a.NoError(err)

	// Peer 2 joins with the assigned token → match → NOTIFY #2 to
	// peer 1 (PEER_MATCHED). Read it on peer1Client.
	assigned, err := decryptNotify(t, peer1Priv, resp1)
	a.NoError(err)
	a.Equal(relaybroker.NotifyTokenAssigned, assigned.Type)
	token := assigned.Token

	peer2IP4 := peer2Client.LocalAddr().(*net.UDPAddr).IP.To4()
	pkt2 := relaybroker.BuildRegister(
		token,
		peer2Pub,
		peer2IP4,
		uint16(peer2Client.LocalAddr().(*net.UDPAddr).Port),
	)
	_, err = peer2Client.WriteToUDP(pkt2, b.Addr())
	a.NoError(err)

	_ = peer1Client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := peer1Client.ReadFromUDP(buf)
	a.NoError(err)
	brokerEph2, _, _, err := relaybroker.ParseNotify(buf[:n])
	a.NoError(err)

	// Each NOTIFY uses a different broker ephemeral key.
	a.NotEqual(brokerEph1, brokerEph2,
		"each NOTIFY must use a fresh broker ephemeral key")

	// Sanity: the second NOTIFY is for peer 1, so peer1Priv can
	// decrypt it.
	peer1Payload, err := decryptNotify(t, peer1Priv, buf[:n])
	a.NoError(err)
	a.Equal(relaybroker.NotifyPeerMatched, peer1Payload.Type)
	a.Equal(peer2Pub, peer1Payload.OtherPeerEphPub)

	_ = peer2Priv // referenced for symmetry
}

func TestRegister_SelfMatch_UpdatesAddr(t *testing.T) {
	a := require.New(t)
	b := newTestBroker(t, time.Minute)
	oldClient := newTestClient(t)
	newClient := newTestClient(t)
	peer1Priv, peer1Pub := peerKey(t)
	peer2Client := newTestClient(t)
	peer2Priv, peer2Pub := peerKey(t)

	token := make([]byte, 16)
	for i := range token {
		token[i] = byte(i + 1)
	}

	oldIP := oldClient.LocalAddr().(*net.UDPAddr).IP.To4()
	pktOld := relaybroker.BuildRegister(
		token, peer1Pub, oldIP,
		uint16(oldClient.LocalAddr().(*net.UDPAddr).Port),
	)
	_, err := oldClient.WriteToUDP(pktOld, b.Addr())
	a.NoError(err)
	time.Sleep(20 * time.Millisecond)

	newIP := newClient.LocalAddr().(*net.UDPAddr).IP.To4()
	pktNew := relaybroker.BuildRegister(
		token, peer1Pub, newIP,
		uint16(newClient.LocalAddr().(*net.UDPAddr).Port),
	)
	_, err = newClient.WriteToUDP(pktNew, b.Addr())
	a.NoError(err)
	time.Sleep(20 * time.Millisecond)

	peer2IP := peer2Client.LocalAddr().(*net.UDPAddr).IP.To4()
	pkt2 := relaybroker.BuildRegister(
		token, peer2Pub, peer2IP,
		uint16(peer2Client.LocalAddr().(*net.UDPAddr).Port),
	)
	resp2 := sendAndRead(t, peer2Client, b.Addr(), pkt2)
	peer2Payload, err := decryptNotify(t, peer2Priv, resp2)
	a.NoError(err)
	a.Equal(relaybroker.NotifyPeerMatched, peer2Payload.Type)

	_ = newClient.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := newClient.ReadFromUDP(buf)
	a.NoError(err)
	payload, err := decryptNotify(t, peer1Priv, buf[:n])
	a.NoError(err)
	a.Equal(relaybroker.NotifyPeerMatched, payload.Type)

	_ = oldClient.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, _, err = oldClient.ReadFromUDP(buf)
	a.Error(err, "NOTIFY must go to rebound address, not the old one")
}

func TestRegister_MatchUsesObservedAddr(t *testing.T) {
	a := require.New(t)
	b := newTestBroker(t, time.Minute)
	peer1Client := newTestClient(t)
	peer1Priv, peer1Pub := peerKey(t)
	peer2Client := newTestClient(t)
	_, peer2Pub := peerKey(t)

	token := make([]byte, 16)
	for i := range token {
		token[i] = byte(i + 1)
	}

	peer1IP := peer1Client.LocalAddr().(*net.UDPAddr).IP.To4()
	pkt1 := relaybroker.BuildRegister(
		token, peer1Pub, peer1IP,
		uint16(peer1Client.LocalAddr().(*net.UDPAddr).Port),
	)
	_, err := peer1Client.WriteToUDP(pkt1, b.Addr())
	a.NoError(err)
	time.Sleep(20 * time.Millisecond)

	claimedIP := net.IPv4(1, 2, 3, 4)
	pkt2 := relaybroker.BuildRegister(token, peer2Pub, claimedIP, 9999)
	_, err = peer2Client.WriteToUDP(pkt2, b.Addr())
	a.NoError(err)

	_ = peer1Client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := peer1Client.ReadFromUDP(buf)
	a.NoError(err)
	payload, err := decryptNotify(t, peer1Priv, buf[:n])
	a.NoError(err)
	a.Equal(relaybroker.NotifyPeerMatched, payload.Type)

	observed := peer2Client.LocalAddr().(*net.UDPAddr)
	a.Equal(observed.IP.To4(), net.IP(payload.IP))
	a.Equal(uint16(observed.Port), payload.Port)
}

func TestRegister_DropsWhenRegistryFull(t *testing.T) {
	a := require.New(t)
	cfg := config.Broker{
		Enabled:         true,
		Address:         "127.0.0.1:0",
		RegistrationTTL: time.Minute,
	}
	b, err := New(cfg, nil)
	a.NoError(err)
	b.maxRegistry = 1
	go b.Run(context.Background())
	t.Cleanup(func() { _ = b.Close() })

	peer1Client := newTestClient(t)
	peer1Priv, peer1Pub := peerKey(t)
	peer2Client := newTestClient(t)
	peer2Priv, peer2Pub := peerKey(t)

	token1 := make([]byte, 16)
	for i := range token1 {
		token1[i] = byte(i + 1)
	}
	token2 := make([]byte, 16)
	for i := range token2 {
		token2[i] = byte(i + 2)
	}

	peer1IP := peer1Client.LocalAddr().(*net.UDPAddr).IP.To4()
	pkt1 := relaybroker.BuildRegister(
		token1, peer1Pub, peer1IP,
		uint16(peer1Client.LocalAddr().(*net.UDPAddr).Port),
	)
	_, err = peer1Client.WriteToUDP(pkt1, b.Addr())
	a.NoError(err)
	time.Sleep(20 * time.Millisecond)

	overflow := newTestClient(t)
	_, overflowPub := peerKey(t)
	overflowIP := overflow.LocalAddr().(*net.UDPAddr).IP.To4()
	pktOverflow := relaybroker.BuildRegister(
		token2, overflowPub, overflowIP,
		uint16(overflow.LocalAddr().(*net.UDPAddr).Port),
	)
	_, err = overflow.WriteToUDP(pktOverflow, b.Addr())
	a.NoError(err)
	time.Sleep(20 * time.Millisecond)

	joiner := newTestClient(t)
	_, joinerPub := peerKey(t)
	joinerIP := joiner.LocalAddr().(*net.UDPAddr).IP.To4()
	pktJoin2 := relaybroker.BuildRegister(
		token2, joinerPub, joinerIP,
		uint16(joiner.LocalAddr().(*net.UDPAddr).Port),
	)
	_, err = joiner.WriteToUDP(pktJoin2, b.Addr())
	a.NoError(err)
	_ = joiner.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1500)
	_, _, err = joiner.ReadFromUDP(buf)
	a.Error(err, "overflow token must not be held")

	peer2IP := peer2Client.LocalAddr().(*net.UDPAddr).IP.To4()
	pkt2 := relaybroker.BuildRegister(
		token1, peer2Pub, peer2IP,
		uint16(peer2Client.LocalAddr().(*net.UDPAddr).Port),
	)
	resp2 := sendAndRead(t, peer2Client, b.Addr(), pkt2)
	payload2, err := decryptNotify(t, peer2Priv, resp2)
	a.NoError(err)
	a.Equal(relaybroker.NotifyPeerMatched, payload2.Type)

	_ = peer1Client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := peer1Client.ReadFromUDP(buf)
	a.NoError(err)
	payload1, err := decryptNotify(t, peer1Priv, buf[:n])
	a.NoError(err)
	a.Equal(relaybroker.NotifyPeerMatched, payload1.Type)
}
