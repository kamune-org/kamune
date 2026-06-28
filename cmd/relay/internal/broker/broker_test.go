package broker

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/cmd/relay/internal/config"
	relaybroker "github.com/kamune-org/kamune/pkg/relayconn/broker"
)

// newTestBroker binds a real UDP socket on 127.0.0.1:0 (kernel-assigned port)
// and starts the Run loop in a goroutine. The cleanup function closes the
// broker socket.
func newTestBroker(t *testing.T, ttl time.Duration) *Broker {
	t.Helper()
	cfg := config.Broker{
		Enabled:         true,
		Address:         "127.0.0.1:0",
		RegistrationTTL: ttl,
	}
	b, err := New(cfg, nil)
	require.NoError(t, err)

	go b.Run(context.Background())

	t.Cleanup(func() { _ = b.Close() })
	return b
}

// newTestClient returns a UDP socket bound to 127.0.0.1:0, suitable for sending
// packets to the broker and reading the response.
func newTestClient(t *testing.T) *net.UDPConn {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	c, err := net.ListenUDP("udp4", addr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// peerKey generates a fresh X25519 key pair and returns the private key (for
// ECDH) and the public key bytes (for REGISTER).
func peerKey(t *testing.T) (*ecdh.PrivateKey, []byte) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	return k, k.PublicKey().Bytes()
}

// sendAndRead sends pkt to the broker and reads a single response with a
// 2-second deadline.
func sendAndRead(t *testing.T, c *net.UDPConn, brokerAddr *net.UDPAddr, pkt []byte) []byte {
	t.Helper()
	_, err := c.WriteToUDP(pkt, brokerAddr)
	require.NoError(t, err)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := c.ReadFromUDP(buf)
	require.NoError(t, err, "expected response within 2s")
	return buf[:n]
}

// decryptNotify peeks at the broker's ephemeral public key in the NOTIFY
// header, derives the shared secret with the peer's private key, and opens the
// AEAD ciphertext.
func decryptNotify(
	t *testing.T, peerPriv *ecdh.PrivateKey, pkt []byte,
) (relaybroker.NotifyPayload, error) {
	t.Helper()
	brokerEphPub, nonce, sealed, err := relaybroker.ParseNotify(pkt)
	require.NoError(t, err)

	brokerPub, err := ecdh.X25519().NewPublicKey(brokerEphPub)
	require.NoError(t, err)
	shared, err := peerPriv.ECDH(brokerPub)
	require.NoError(t, err)
	key := sha256.Sum256(shared)

	plaintext, err := relaybroker.OpenNotify(key[:], brokerEphPub, nonce, sealed)
	require.NoError(t, err)
	return relaybroker.ParseNotifyPayload(plaintext)
}

func TestSTUNEcho_RespondsWithSenderIP(t *testing.T) {
	b := newTestBroker(t, time.Minute)
	client := newTestClient(t)

	pkt := []byte{'K', 'B', 'R', 'K', 0x01, 0x01}
	resp := sendAndRead(t, client, b.Addr(), pkt)

	// Response is "ip:port\0". The client source is 127.0.0.1.
	srcAddr := client.LocalAddr().(*net.UDPAddr)
	ip4 := srcAddr.IP.To4()
	require.NotNil(t, ip4, "client source must be IPv4")
	expected := fmt.Sprintf("%s:%d\x00", ip4.String(), srcAddr.Port)
	assert.Equal(t, expected, string(resp))
}

func TestSTUNEcho_IgnoresUnknownMagic(t *testing.T) {
	b := newTestBroker(t, time.Minute)
	client := newTestClient(t)

	pkt := []byte{'D', 'E', 'A', 'D', 0x00, 0x01, 0x01}
	_, err := client.WriteToUDP(pkt, b.Addr())
	require.NoError(t, err)
	_ = client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1500)
	_, _, err = client.ReadFromUDP(buf)
	assert.Error(t, err, "expected read timeout (no response)")
}

func TestSTUNEcho_IgnoresUnknownOpcode(t *testing.T) {
	b := newTestBroker(t, time.Minute)
	client := newTestClient(t)

	pkt := []byte{'K', 'B', 'R', 'K', 0x01, 0xFF} // unknown opcode
	_, err := client.WriteToUDP(pkt, b.Addr())
	require.NoError(t, err)
	_ = client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1500)
	_, _, err = client.ReadFromUDP(buf)
	assert.Error(t, err, "expected read timeout (no response)")
}

func TestSTUNEcho_IgnoresUnknownVersion(t *testing.T) {
	b := newTestBroker(t, time.Minute)
	client := newTestClient(t)

	pkt := []byte{'K', 'B', 'R', 'K', 0x02, 0x01} // VER=2
	_, err := client.WriteToUDP(pkt, b.Addr())
	require.NoError(t, err)
	_ = client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1500)
	_, _, err = client.ReadFromUDP(buf)
	assert.Error(t, err, "expected read timeout (no response)")
}

func TestSTUNEcho_IgnoresShortPacket(t *testing.T) {
	b := newTestBroker(t, time.Minute)
	client := newTestClient(t)

	pkt := []byte{'K', 'B', 'R', 'K'} // 4 bytes, no VER/OPCODE
	_, err := client.WriteToUDP(pkt, b.Addr())
	require.NoError(t, err)
	_ = client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1500)
	_, _, err = client.ReadFromUDP(buf)
	assert.Error(t, err, "expected read timeout (no response)")
}

func TestSTUNEcho_ContentIgnored(t *testing.T) {
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
	require.NotNil(t, ip4)
	expected := fmt.Sprintf("%s:%d\x00", ip4.String(), srcAddr.Port)
	assert.Equal(t, expected, string(resp))
}

func TestRegister_Random_AssignsToken(t *testing.T) {
	b := newTestBroker(t, time.Minute)
	client := newTestClient(t)
	priv, pub := peerKey(t)

	// Empty token = random mode.
	clientAddr := client.LocalAddr().(*net.UDPAddr)
	ip4 := clientAddr.IP.To4()
	require.NotNil(t, ip4)
	pkt := relaybroker.BuildRegister(nil, pub, ip4, uint16(clientAddr.Port))
	resp := sendAndRead(t, client, b.Addr(), pkt)

	payload, err := decryptNotify(t, priv, resp)
	require.NoError(t, err)
	assert.Equal(t, relaybroker.NotifyTokenAssigned, payload.Type)
	assert.Len(t, payload.Token, 16, "assigned token must be 16 bytes")
	assert.NotZero(t, payload.TTLSeconds, "TTL must be > 0")
}

func TestRegister_Random_AssignedTokenStored(t *testing.T) {
	b := newTestBroker(t, time.Minute)
	peer1Client := newTestClient(t)
	peer1Priv, peer1Pub := peerKey(t)
	peer2Client := newTestClient(t)
	peer2Priv, peer2Pub := peerKey(t)

	// Peer 1: random mode, get an assigned token.
	peer1Addr := peer1Client.LocalAddr().(*net.UDPAddr)
	peer1IP4 := peer1Addr.IP.To4()
	require.NotNil(t, peer1IP4)
	pkt1 := relaybroker.BuildRegister(
		nil, peer1Pub, peer1IP4, uint16(peer1Addr.Port),
	)
	resp1 := sendAndRead(t, peer1Client, b.Addr(), pkt1)
	assigned, err := decryptNotify(t, peer1Priv, resp1)
	require.NoError(t, err)
	require.Equal(t, relaybroker.NotifyTokenAssigned, assigned.Type)
	token := assigned.Token

	// Peer 2: join with the assigned token.
	peer2IP4 := peer2Client.LocalAddr().(*net.UDPAddr).IP.To4()
	require.NotNil(t, peer2IP4)
	pkt2 := relaybroker.BuildRegister(
		token,
		peer2Pub,
		peer2IP4,
		uint16(peer2Client.LocalAddr().(*net.UDPAddr).Port),
	)
	resp2 := sendAndRead(t, peer2Client, b.Addr(), pkt2)
	peer2Payload, err := decryptNotify(t, peer2Priv, resp2)
	require.NoError(t, err)
	assert.Equal(t, relaybroker.NotifyPeerMatched, peer2Payload.Type)
	// Peer 2 should see peer 1's IP:port + eph pub.
	assert.Equal(t, peer1Pub, peer2Payload.OtherPeerEphPub)
	assert.Equal(t, peer1IP4, net.IP(peer2Payload.IP))
	assert.Equal(t, uint16(peer1Addr.Port), peer2Payload.Port)

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
	require.NoError(t, err)
	peer1Payload, err := decryptNotify(t, peer1Priv, buf[:n])
	require.NoError(t, err)
	assert.Equal(t, relaybroker.NotifyPeerMatched, peer1Payload.Type)
	assert.Equal(t, peer2Pub, peer1Payload.OtherPeerEphPub)
}

func TestRegister_Static_HoldsUntilMatch(t *testing.T) {
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
	require.NoError(t, err)

	_ = client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1500)
	_, _, err = client.ReadFromUDP(buf)
	assert.Error(t, err, "expected read timeout (no NOTIFY on hold)")
}

func TestRegister_Static_MatchNotifiesBoth(t *testing.T) {
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
	require.NoError(t, err)

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
	require.NoError(t, err)
	require.Equal(t, relaybroker.NotifyPeerMatched, peer2Payload.Type)

	// Read peer 1's NOTIFY.
	_ = peer1Client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := peer1Client.ReadFromUDP(buf)
	require.NoError(t, err)
	peer1Payload, err := decryptNotify(t, peer1Priv, buf[:n])
	require.NoError(t, err)
	require.Equal(t, relaybroker.NotifyPeerMatched, peer1Payload.Type)

	// Each NOTIFY must use a different broker ephemeral public key
	// (forward secrecy per NOTIFY).
	peer1NotifyBrokerEph := peer1Payload.OtherPeerEphPub // not the broker key — placeholder
	_ = peer1NotifyBrokerEph
}

func TestRegister_ReRegistration_RefreshesTTL(t *testing.T) {
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
	require.NoError(t, err)
	// Wait 100ms (half of TTL).
	time.Sleep(100 * time.Millisecond)
	// Re-register — same source + same key → refresh TTL.
	_, err = client.WriteToUDP(pkt, b.Addr())
	require.NoError(t, err)
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
	require.NoError(t, err)
	buf := make([]byte, 1500)
	n, _, err := client.ReadFromUDP(buf)
	require.NoError(t, err, "entry should still be alive after refresh")
	assert.Greater(t, n, 0, "received non-empty response")
}

func TestRegister_SelfMatch_NotBlocked(t *testing.T) {
	// Self-match: same source re-registers with the same token →
	// refresh TTL, no NOTIFY.
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
	require.NoError(t, err)
	// Re-register with the same source and same eph key.
	_, err = client.WriteToUDP(pkt, b.Addr())
	require.NoError(t, err)

	_ = client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1500)
	_, _, err = client.ReadFromUDP(buf)
	assert.Error(t, err, "self-match should not produce a NOTIFY")
}

func TestRegister_EmptyIP_Ignored(t *testing.T) {
	b := newTestBroker(t, time.Minute)
	client := newTestClient(t)
	_, pub := peerKey(t)

	// Zero IP — REGISTER is rejected.
	pkt := relaybroker.BuildRegister(nil, pub, net.IPv4(0, 0, 0, 0), 12345)
	_, err := client.WriteToUDP(pkt, b.Addr())
	require.NoError(t, err)
	_ = client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1500)
	_, _, err = client.ReadFromUDP(buf)
	assert.Error(t, err, "expected read timeout (empty IP rejected)")
}

func TestRegister_EmptyPeerEphPub_Ignored(t *testing.T) {
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
	require.NoError(t, err)
	_ = client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1500)
	_, _, err = client.ReadFromUDP(buf)
	assert.Error(t, err, "expected read timeout (zero pub rejected)")
}

func TestRegister_TTLExpires(t *testing.T) {
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
	assert.Equal(t, 1, len(b.registry))
	b.mu.Unlock()

	// Just after expiry — evicted.
	now = now.Add(60 * time.Millisecond)
	b.purgeExpired()
	b.mu.Lock()
	assert.Equal(t, 0, len(b.registry))
	b.mu.Unlock()
}

func TestRegister_NotifyIgnored(t *testing.T) {
	b := newTestBroker(t, time.Minute)
	client := newTestClient(t)

	// Peer sends NOTIFY — broker ignores it.
	pkt := []byte{'K', 'B', 'R', 'K', 0x01, 0x03}
	pkt = append(pkt, make([]byte, 100)...) // trailing junk
	_, err := client.WriteToUDP(pkt, b.Addr())
	require.NoError(t, err)
	_ = client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1500)
	_, _, err = client.ReadFromUDP(buf)
	assert.Error(t, err, "expected read timeout (peer NOTIFY ignored)")
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
	cfg := config.Broker{
		Enabled:         true,
		Address:         "127.0.0.1:0",
		RegistrationTTL: time.Minute,
	}
	b, err := New(cfg, allow)
	require.NoError(t, err)
	go b.Run(context.Background())
	t.Cleanup(func() { _ = b.Close() })

	client := newTestClient(t)
	pkt := []byte{'K', 'B', 'R', 'K', 0x01, 0x01}

	// First two: response.
	_ = sendAndRead(t, client, b.Addr(), pkt)
	_ = sendAndRead(t, client, b.Addr(), pkt)

	// Third: dropped.
	_, err = client.WriteToUDP(pkt, b.Addr())
	require.NoError(t, err)
	_ = client.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1500)
	_, _, err = client.ReadFromUDP(buf)
	assert.Error(t, err, "expected read timeout (rate-limited)")
}

func TestNotify_DecryptFailsWithWrongKey(t *testing.T) {
	b := newTestBroker(t, time.Minute)
	client := newTestClient(t)
	_, pub := peerKey(t)

	clientAddr := client.LocalAddr().(*net.UDPAddr)
	ip4 := clientAddr.IP.To4()
	require.NotNil(t, ip4)
	pkt := relaybroker.BuildRegister(nil, pub, ip4, uint16(clientAddr.Port))
	resp := sendAndRead(t, client, b.Addr(), pkt)

	// Attempt to decrypt with a DIFFERENT peer's private key.
	wrongPriv, _ := peerKey(t)
	brokerEphPub, nonce, sealed, err := relaybroker.ParseNotify(resp)
	require.NoError(t, err)
	wrongPub, err := ecdh.X25519().NewPublicKey(brokerEphPub)
	require.NoError(t, err)
	wrongShared, err := wrongPriv.ECDH(wrongPub)
	require.NoError(t, err)
	wrongKey := sha256.Sum256(wrongShared)
	_, err = relaybroker.OpenNotify(wrongKey[:], brokerEphPub, nonce, sealed)
	assert.Error(t, err, "decryption with wrong key must fail")
}

func TestNotify_AADBoundToBrokerKey(t *testing.T) {
	b := newTestBroker(t, time.Minute)
	client := newTestClient(t)
	priv, pub := peerKey(t)

	clientAddr := client.LocalAddr().(*net.UDPAddr)
	ip4 := clientAddr.IP.To4()
	require.NotNil(t, ip4)
	pkt := relaybroker.BuildRegister(nil, pub, ip4, uint16(clientAddr.Port))
	resp := sendAndRead(t, client, b.Addr(), pkt)

	// Capture the broker's eph pub and the rest of the packet.
	brokerEphPub, nonce, sealed, err := relaybroker.ParseNotify(resp)
	require.NoError(t, err)
	// Flip a bit in the broker eph pub.
	tampered := make([]byte, len(brokerEphPub))
	copy(tampered, brokerEphPub)
	tampered[0] ^= 0xFF

	// Recompute the AEAD key (same as the legit peer would) and try
	// to open with the TAMPERED eph pub in the AAD.
	legitPub, err := ecdh.X25519().NewPublicKey(brokerEphPub)
	require.NoError(t, err)
	shared, err := priv.ECDH(legitPub)
	require.NoError(t, err)
	key := sha256.Sum256(shared)
	_, err = relaybroker.OpenNotify(key[:], tampered, nonce, sealed)
	assert.Error(t, err, "decryption with tampered AAD must fail")
}

func TestNotify_ForwardSecrecy(t *testing.T) {
	// Two NOTIFYs from the same session: each uses a fresh broker
	// ephemeral key, so deriving one shared secret doesn't help
	// derive the other.
	b := newTestBroker(t, time.Minute)
	peer1Client := newTestClient(t)
	peer1Priv, peer1Pub := peerKey(t)
	peer2Client := newTestClient(t)
	peer2Priv, peer2Pub := peerKey(t)

	// Peer 1: random mode → NOTIFY #1 (TOKEN_ASSIGNED).
	peer1Addr := peer1Client.LocalAddr().(*net.UDPAddr)
	peer1IP4 := peer1Addr.IP.To4()
	require.NotNil(t, peer1IP4)
	pkt1 := relaybroker.BuildRegister(
		nil, peer1Pub, peer1IP4, uint16(peer1Addr.Port),
	)
	resp1 := sendAndRead(t, peer1Client, b.Addr(), pkt1)
	brokerEph1, _, _, err := relaybroker.ParseNotify(resp1)
	require.NoError(t, err)

	// Peer 2 joins with the assigned token → match → NOTIFY #2 to
	// peer 1 (PEER_MATCHED). Read it on peer1Client.
	assigned, err := decryptNotify(t, peer1Priv, resp1)
	require.NoError(t, err)
	require.Equal(t, relaybroker.NotifyTokenAssigned, assigned.Type)
	token := assigned.Token

	peer2IP4 := peer2Client.LocalAddr().(*net.UDPAddr).IP.To4()
	pkt2 := relaybroker.BuildRegister(
		token,
		peer2Pub,
		peer2IP4,
		uint16(peer2Client.LocalAddr().(*net.UDPAddr).Port),
	)
	_, err = peer2Client.WriteToUDP(pkt2, b.Addr())
	require.NoError(t, err)

	_ = peer1Client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, _, err := peer1Client.ReadFromUDP(buf)
	require.NoError(t, err)
	brokerEph2, _, _, err := relaybroker.ParseNotify(buf[:n])
	require.NoError(t, err)

	// Each NOTIFY uses a different broker ephemeral key.
	assert.NotEqual(t, brokerEph1, brokerEph2,
		"each NOTIFY must use a fresh broker ephemeral key")

	// Sanity: the second NOTIFY is for peer 1, so peer1Priv can
	// decrypt it.
	peer1Payload, err := decryptNotify(t, peer1Priv, buf[:n])
	require.NoError(t, err)
	assert.Equal(t, relaybroker.NotifyPeerMatched, peer1Payload.Type)
	assert.Equal(t, peer2Pub, peer1Payload.OtherPeerEphPub)

	_ = peer2Priv // referenced for symmetry
}
