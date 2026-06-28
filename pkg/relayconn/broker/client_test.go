package broker

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testBroker stands in for the production broker. It listens on a real UDP
// socket and answers STUN_ECHO + REGISTER with hand-crafted NOTIFYs (using a
// real X25519 + XChaCha20-Poly1305 encryption).
//
// This is the minimum needed to test the client end-to-end without importing
// cmd/relay/internal/broker.
type testBroker struct {
	conn *net.UDPConn
	addr *net.UDPAddr
	key  *ecdh.PrivateKey
}

func newTestBroker(t *testing.T) *testBroker {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	conn, err := net.ListenUDP("udp4", addr)
	require.NoError(t, err)
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return &testBroker{
		conn: conn,
		addr: conn.LocalAddr().(*net.UDPAddr),
		key:  key,
	}
}

func (b *testBroker) readOne(
	t *testing.T, timeout time.Duration,
) ([]byte, *net.UDPAddr) {
	t.Helper()
	_ = b.conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1500)
	n, src, err := b.conn.ReadFromUDP(buf)
	require.NoError(t, err)
	return buf[:n], src
}

// respondEcho sends `ip:port\0` to src.
func (b *testBroker) respondEcho(t *testing.T, src *net.UDPAddr) {
	t.Helper()
	resp := append([]byte(src.IP.String()+":"+fmt.Sprintf("%d", src.Port)), 0)
	_, err := b.conn.WriteToUDP(resp, src)
	require.NoError(t, err)
}

// respondAssignedToken sends a NOTIFY(TOKEN_ASSIGNED) to the peer whose
// ephemeral public key is peerEphPub. The token is generated randomly.
func (b *testBroker) respondAssignedToken(
	t *testing.T, src *net.UDPAddr, peerEphPub []byte,
) []byte {
	t.Helper()
	token := make([]byte, 16)
	_, err := rand.Read(token)
	require.NoError(t, err)
	b.sendNotifyTokenAssigned(t, src, peerEphPub, token, 60)
	return token
}

// respondPeerMatched sends a NOTIFY(PEER_MATCHED) to the peer whose ephemeral
// public key is peerEphPub, carrying the other peer's IP:port + eph pub.
func (b *testBroker) respondPeerMatched(
	t *testing.T, src *net.UDPAddr, peerEphPub []byte,
	otherEphPub []byte, otherIP net.IP, otherPort uint16,
) {
	t.Helper()
	b.sendNotifyPeerMatched(t, src, peerEphPub, nil, otherEphPub, otherIP, otherPort)
}

// sendNotifyTokenAssigned is the same flow as the production broker: generate a
// fresh ephemeral key, ECDH, AEAD, build NOTIFY.
func (b *testBroker) sendNotifyTokenAssigned(
	t *testing.T, dst *net.UDPAddr, peerEphPub, token []byte, ttlSeconds uint32,
) {
	t.Helper()
	plaintext := TokenAssignedPlaintext(token, ttlSeconds)
	b.sendNotify(t, plaintext, dst, peerEphPub)
}

func (b *testBroker) sendNotifyPeerMatched(
	t *testing.T, dst *net.UDPAddr, peerEphPub, token, otherEphPub []byte,
	otherIP net.IP, otherPort uint16,
) {
	t.Helper()
	plaintext := PeerMatchedPlaintext(token, otherEphPub, otherIP, otherPort)
	b.sendNotify(t, plaintext, dst, peerEphPub)
}

func (b *testBroker) sendNotify(
	t *testing.T, plaintext []byte, dst *net.UDPAddr, peerEphPub []byte,
) {
	t.Helper()
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	peerPub, err := ecdh.X25519().NewPublicKey(peerEphPub)
	require.NoError(t, err)
	shared, err := eph.ECDH(peerPub)
	require.NoError(t, err)
	key := sha256.Sum256(shared)
	brokerEphPub := eph.PublicKey().Bytes()
	nonce, sealed := SealNotify(key[:], brokerEphPub, plaintext)
	var pkt []byte
	switch NotifyType(plaintext[0]) {
	case NotifyPeerMatched:
		pkt = BuildNotifyPeerMatched(brokerEphPub, nonce, sealed)
	case NotifyTokenAssigned:
		pkt = BuildNotifyTokenAssigned(brokerEphPub, nonce, sealed)
	}
	_, err = b.conn.WriteToUDP(pkt, dst)
	require.NoError(t, err)
}

// --- Client tests ---------------------------------------------------------

func TestClient_Echo(t *testing.T) {
	tb := newTestBroker(t)
	c, err := NewClient(tb.addr.String())
	require.NoError(t, err)

	// Run the test broker in a goroutine: read one packet, respond
	// with `ip:port\0`.
	go func() {
		_, src := tb.readOne(t, 2*time.Second)
		tb.respondEcho(t, src)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ip, port, err := c.Echo(ctx)
	require.NoError(t, err)
	// The client dials from 127.0.0.1:PORTA → broker 127.0.0.1:PORTB. Echo
	// response is the source IP:port as seen by the broker.
	assert.Equal(t, "127.0.0.1", ip.String())
	assert.NotZero(t, port)
}

func TestClient_Register_Random_AssignsToken(t *testing.T) {
	tb := newTestBroker(t)
	c, err := NewClient(tb.addr.String())
	require.NoError(t, err)

	expectedToken := make([]byte, 16)
	for i := range expectedToken {
		expectedToken[i] = byte(i + 1)
	}

	go func() {
		_, src := tb.readOne(t, 2*time.Second)
		// Token is generated server-side; the client just receives whatever the
		// broker sends. We use a fixed pattern for assertion.
		tb.sendNotifyTokenAssigned(t, src, c.PublicKey(), expectedToken, 60)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ip4 := net.IPv4(127, 0, 0, 1)
	got, err := c.Register(ctx, nil, ip4, 12345)
	require.NoError(t, err)
	assert.Equal(t, expectedToken, got)
}

func TestClient_Register_Static_NoResponse(t *testing.T) {
	tb := newTestBroker(t)
	c, err := NewClient(tb.addr.String())
	require.NoError(t, err)

	token := make([]byte, 16)
	for i := range token {
		token[i] = byte(i + 1)
	}

	// Static mode: the broker sends no response. Verify the client
	// returns the input token without hanging.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ip4 := net.IPv4(127, 0, 0, 1)
	got, err := c.Register(ctx, token, ip4, 12345)
	require.NoError(t, err)
	assert.Equal(t, token, got)
}

func TestClient_Listen_ReceivesPeerMatched(t *testing.T) {
	tb := newTestBroker(t)
	c, err := NewClient(tb.addr.String())
	require.NoError(t, err)

	ctx := t.Context()
	out, clientAddr, err := c.Listen(ctx)
	require.NoError(t, err)
	require.NotNil(t, clientAddr)

	// Send a NOTIFY(PEER_MATCHED) to the client.
	otherEph, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	tb.respondPeerMatched(
		t, clientAddr, c.PublicKey(),
		otherEph.PublicKey().Bytes(),
		net.IPv4(192, 0, 2, 1), 54321,
	)

	select {
	case p, ok := <-out:
		require.True(t, ok, "channel should not be closed yet")
		assert.Equal(t, NotifyPeerMatched, p.Type)
		assert.Equal(t, otherEph.PublicKey().Bytes(), p.OtherPeerEphPub)
		assert.Equal(t, "192.0.2.1", p.IP.String())
		assert.Equal(t, uint16(54321), p.Port)
	case <-time.After(2 * time.Second):
		t.Fatal("did not receive NOTIFY within 2s")
	}
}

func TestClient_Listen_ReceivesTokenAssigned(t *testing.T) {
	tb := newTestBroker(t)
	c, err := NewClient(tb.addr.String())
	require.NoError(t, err)

	ctx := t.Context()
	out, clientAddr, err := c.Listen(ctx)
	require.NoError(t, err)

	assigned := make([]byte, 16)
	for i := range assigned {
		assigned[i] = byte(i + 1)
	}
	tb.sendNotifyTokenAssigned(t, clientAddr, c.PublicKey(), assigned, 60)

	select {
	case p, ok := <-out:
		require.True(t, ok)
		assert.Equal(t, NotifyTokenAssigned, p.Type)
		assert.Equal(t, assigned, p.Token)
		assert.Equal(t, uint32(60), p.TTLSeconds)
	case <-time.After(2 * time.Second):
		t.Fatal("did not receive NOTIFY within 2s")
	}
}

func TestClient_Listen_RejectsWrongKey(t *testing.T) {
	tb := newTestBroker(t)
	c, err := NewClient(tb.addr.String())
	require.NoError(t, err)

	ctx := t.Context()
	out, clientAddr, err := c.Listen(ctx)
	require.NoError(t, err)

	// Send a NOTIFY encrypted for a DIFFERENT peer eph pub.
	wrongEph, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	otherEph, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	tb.respondPeerMatched(
		t, clientAddr, wrongEph.PublicKey().Bytes(),
		otherEph.PublicKey().Bytes(),
		net.IPv4(192, 0, 2, 1), 54321,
	)

	// The client's listen loop should silently drop the bad
	// packet; no payload should be emitted on the channel within
	// 500ms (the read deadline). Verify by reading a different
	// event in that window.
	select {
	case _, ok := <-out:
		if ok {
			t.Fatal("client emitted a payload for a NOTIFY encrypted with a wrong key")
		}
	case <-time.After(700 * time.Millisecond):
		// Expected: no payload within the read deadline.
	}
}

func TestClient_PublicKey_Stable(t *testing.T) {
	c, err := NewClient("127.0.0.1:0")
	require.NoError(t, err)
	k1 := c.PublicKey()
	k2 := c.PublicKey()
	assert.True(t, bytes.Equal(k1, k2), "PublicKey must be stable")
	assert.Len(t, k1, 32)
}
