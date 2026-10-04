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
	a := require.New(t)
	addr, err := net.ResolveUDPAddr("udp4", "127.0.0.1:0")
	a.NoError(err)
	conn, err := net.ListenUDP("udp4", addr)
	a.NoError(err)
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	a.NoError(err)
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
	a := require.New(t)
	_ = b.conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1500)
	n, src, err := b.conn.ReadFromUDP(buf)
	a.NoError(err)
	return buf[:n], src
}

// respondEcho sends `ip:port\0` to src.
func (b *testBroker) respondEcho(t *testing.T, src *net.UDPAddr) {
	t.Helper()
	a := require.New(t)
	resp := append([]byte(src.IP.String()+":"+fmt.Sprintf("%d", src.Port)), 0)
	_, err := b.conn.WriteToUDP(resp, src)
	a.NoError(err)
}

// respondAssignedToken sends a NOTIFY(TOKEN_ASSIGNED) to the peer whose
// ephemeral public key is peerEphPub. The token is generated randomly.
func (b *testBroker) respondAssignedToken(
	t *testing.T, src *net.UDPAddr, peerEphPub []byte,
) []byte {
	t.Helper()
	a := require.New(t)
	token := make([]byte, 16)
	_, err := rand.Read(token)
	a.NoError(err)
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
	a := require.New(t)
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	a.NoError(err)
	peerPub, err := ecdh.X25519().NewPublicKey(peerEphPub)
	a.NoError(err)
	shared, err := eph.ECDH(peerPub)
	a.NoError(err)
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
	a.NoError(err)
}

// --- Client tests ---------------------------------------------------------

func TestClient_Echo(t *testing.T) {
	a := require.New(t)
	tb := newTestBroker(t)
	c, err := NewClient(tb.addr.String())
	a.NoError(err)

	go func() {
		_, src := tb.readOne(t, 2*time.Second)
		tb.respondEcho(t, src)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ip, port, err := c.Echo(ctx)
	a.NoError(err)
	a.Equal("127.0.0.1", ip.String())
	a.NotZero(port)
}

func TestClient_Register_Random_AssignsToken(t *testing.T) {
	a := require.New(t)
	tb := newTestBroker(t)
	c, err := NewClient(tb.addr.String())
	a.NoError(err)

	expectedToken := make([]byte, 16)
	for i := range expectedToken {
		expectedToken[i] = byte(i + 1)
	}

	go func() {
		_, src := tb.readOne(t, 2*time.Second)
		tb.sendNotifyTokenAssigned(t, src, c.PublicKey(), expectedToken, 60)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ip4 := net.IPv4(127, 0, 0, 1)
	got, err := c.Register(ctx, nil, ip4, 12345)
	a.NoError(err)
	a.Equal(expectedToken, got)
}

func TestClient_Register_Static_NoResponse(t *testing.T) {
	a := require.New(t)
	tb := newTestBroker(t)
	c, err := NewClient(tb.addr.String())
	a.NoError(err)

	token := make([]byte, 16)
	for i := range token {
		token[i] = byte(i + 1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ip4 := net.IPv4(127, 0, 0, 1)
	got, err := c.Register(ctx, token, ip4, 12345)
	a.NoError(err)
	a.Equal(token, got)
}

func TestClient_Listen_ReceivesPeerMatched(t *testing.T) {
	a := require.New(t)
	tb := newTestBroker(t)
	c, err := NewClient(tb.addr.String())
	a.NoError(err)

	ctx := t.Context()
	out, clientAddr, err := c.Listen(ctx)
	a.NoError(err)
	a.NotNil(clientAddr)

	otherEph, err := ecdh.X25519().GenerateKey(rand.Reader)
	a.NoError(err)
	tb.respondPeerMatched(
		t, clientAddr, c.PublicKey(),
		otherEph.PublicKey().Bytes(),
		net.IPv4(192, 0, 2, 1), 54321,
	)

	select {
	case p, ok := <-out:
		a.True(ok, "channel should not be closed yet")
		a.Equal(NotifyPeerMatched, p.Type)
		a.Equal(otherEph.PublicKey().Bytes(), p.OtherPeerEphPub)
		a.Equal("192.0.2.1", p.IP.String())
		a.Equal(uint16(54321), p.Port)
	case <-time.After(2 * time.Second):
		a.Fail("did not receive NOTIFY within 2s")
	}
}

func TestClient_Listen_ReceivesTokenAssigned(t *testing.T) {
	a := require.New(t)
	tb := newTestBroker(t)
	c, err := NewClient(tb.addr.String())
	a.NoError(err)

	ctx := t.Context()
	out, clientAddr, err := c.Listen(ctx)
	a.NoError(err)

	assigned := make([]byte, 16)
	for i := range assigned {
		assigned[i] = byte(i + 1)
	}
	tb.sendNotifyTokenAssigned(t, clientAddr, c.PublicKey(), assigned, 60)

	select {
	case p, ok := <-out:
		a.True(ok)
		a.Equal(NotifyTokenAssigned, p.Type)
		a.Equal(assigned, p.Token)
		a.Equal(uint32(60), p.TTLSeconds)
	case <-time.After(2 * time.Second):
		a.Fail("did not receive NOTIFY within 2s")
	}
}

func TestClient_Listen_RejectsWrongKey(t *testing.T) {
	a := require.New(t)
	tb := newTestBroker(t)
	c, err := NewClient(tb.addr.String())
	a.NoError(err)

	ctx := t.Context()
	out, clientAddr, err := c.Listen(ctx)
	a.NoError(err)

	wrongEph, err := ecdh.X25519().GenerateKey(rand.Reader)
	a.NoError(err)
	otherEph, err := ecdh.X25519().GenerateKey(rand.Reader)
	a.NoError(err)
	tb.respondPeerMatched(
		t, clientAddr, wrongEph.PublicKey().Bytes(),
		otherEph.PublicKey().Bytes(),
		net.IPv4(192, 0, 2, 1), 54321,
	)

	select {
	case _, ok := <-out:
		if ok {
			a.Fail("client emitted a payload for a NOTIFY encrypted with a wrong key")
		}
	case <-time.After(700 * time.Millisecond):
		// Expected: no payload within the read deadline.
	}
}

func TestClient_PublicKey_Stable(t *testing.T) {
	a := require.New(t)
	c, err := NewClient("127.0.0.1:0")
	a.NoError(err)
	k1 := c.PublicKey()
	k2 := c.PublicKey()
	a.True(bytes.Equal(k1, k2), "PublicKey must be stable")
	a.Len(k1, 32)
}

// TestClient_Register_Static_ImmediateReply answers a static REGISTER at
// once, as the broker does when a peer already holds the token, and
// checks that Register decodes only the received packet and does not
// fail on a reply other than TOKEN_ASSIGNED.
func TestClient_Register_Static_ImmediateReply(t *testing.T) {
	token := make([]byte, 16)
	for i := range token {
		token[i] = byte(i + 1)
	}
	otherEph, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.New(t).NoError(err)

	tests := []struct {
		reply func(tb *testBroker, src *net.UDPAddr, pub []byte) []byte
		name  string
	}{
		{
			name: "token assigned",
			reply: func(tb *testBroker, src *net.UDPAddr, pub []byte) []byte {
				return tb.respondAssignedToken(t, src, pub)
			},
		},
		{
			name: "peer matched",
			reply: func(tb *testBroker, src *net.UDPAddr, pub []byte) []byte {
				tb.respondPeerMatched(
					t, src, pub, otherEph.PublicKey().Bytes(),
					net.IPv4(192, 0, 2, 1), 54321,
				)
				return token
			},
		},
		{
			name: "garbage",
			reply: func(tb *testBroker, src *net.UDPAddr, _ []byte) []byte {
				_, err := tb.conn.WriteToUDP([]byte("KBRK\x01\x03junk"), src)
				require.New(t).NoError(err)
				return token
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			tb := newTestBroker(t)
			c, err := NewClient(tb.addr.String())
			a.NoError(err)

			want := make(chan []byte, 1)
			go func() {
				_, src := tb.readOne(t, 2*time.Second)
				want <- tc.reply(tb, src, c.PublicKey())
			}()

			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			got, err := c.Register(ctx, token, net.IPv4(127, 0, 0, 1), 12345)
			a.NoError(err)
			a.Equal(<-want, got)
		})
	}
}

// --- Caller-owned socket ---------------------------------------------------

// punchSocket opens the unconnected UDP socket a peer would punch from.
func punchSocket(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.New(t).NoError(err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// stranger sends pkt to dst from a socket other than the broker's.
func stranger(t *testing.T, dst *net.UDPAddr, pkt []byte) {
	t.Helper()
	a := require.New(t)
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	a.NoError(err)
	defer conn.Close()
	_, err = conn.WriteToUDP(pkt, dst)
	a.NoError(err)
}

// sealNotify seals plaintext into a NOTIFY for the peer whose ephemeral
// public key is peerEphPub, as the broker would.
func sealNotify(t *testing.T, peerEphPub, plaintext []byte) []byte {
	t.Helper()
	a := require.New(t)
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	a.NoError(err)
	peerPub, err := ecdh.X25519().NewPublicKey(peerEphPub)
	a.NoError(err)
	shared, err := eph.ECDH(peerPub)
	a.NoError(err)
	key := sha256.Sum256(shared)
	brokerEphPub := eph.PublicKey().Bytes()
	nonce, sealed := SealNotify(key[:], brokerEphPub, plaintext)
	return buildNotify(brokerEphPub, nonce, sealed, 0)
}

// sealedPeerMatched builds a PEER_MATCHED NOTIFY for the peer whose
// ephemeral public key is peerEphPub, naming port as the other peer's.
func sealedPeerMatched(
	t *testing.T, peerEphPub []byte, port uint16,
) []byte {
	t.Helper()
	other, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.New(t).NoError(err)
	return sealNotify(t, peerEphPub, PeerMatchedPlaintext(
		nil, other.PublicKey().Bytes(), net.IPv4(192, 0, 2, 1), port,
	))
}

// TestClient_EchoOn checks that the echo goes out from the caller's
// socket and that EchoOn reports that socket's address.
func TestClient_EchoOn(t *testing.T) {
	a := require.New(t)
	tb := newTestBroker(t)
	c, err := NewClient(tb.addr.String())
	a.NoError(err)
	conn := punchSocket(t)
	local := conn.LocalAddr().(*net.UDPAddr)

	done := make(chan struct{})
	defer func() { <-done }()
	go func() {
		defer close(done)
		_, src := tb.readOne(t, 2*time.Second)
		stranger(t, src, []byte("10.0.0.1:1\x00"))
		tb.respondEcho(t, src)
	}()

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	ip, port, err := c.EchoOn(ctx, conn)
	a.NoError(err)
	a.Equal("127.0.0.1", ip.String())
	a.Equal(uint16(local.Port), port)
}

// TestClient_RegisterOn registers from the caller's socket and checks
// that the broker sees that socket as the source, that random mode
// returns the assigned token while ignoring packets from other sources,
// and that the PEER_MATCHED of a static registration reaches the same
// socket through ReadNotify.
func TestClient_RegisterOn(t *testing.T) {
	static := make([]byte, 32)
	for i := range static {
		static[i] = byte(i + 1)
	}
	zeroWire := append(make([]byte, TokenSize), 0x01)
	assigned := bytes.Repeat([]byte{0x7a}, TokenSize)

	tests := []struct {
		token     []byte
		name      string
		wantToken []byte
		random    bool
	}{
		{name: "random", token: nil, wantToken: assigned, random: true},
		{
			name:  "zero wire token",
			token: zeroWire, wantToken: assigned, random: true,
		},
		{name: "static", token: static, wantToken: static},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			tb := newTestBroker(t)
			c, err := NewClient(tb.addr.String())
			a.NoError(err)
			conn := punchSocket(t)
			local := conn.LocalAddr().(*net.UDPAddr)

			srcCh := make(chan *net.UDPAddr, 1)
			done := make(chan struct{})
			defer func() { <-done }()
			go func() {
				defer close(done)
				_, src := tb.readOne(t, 2*time.Second)
				srcCh <- src
				if tc.random {
					// A TOKEN_ASSIGNED from another source must
					// not be taken for the broker's reply.
					stranger(t, src, sealNotify(
						t, c.PublicKey(),
						TokenAssignedPlaintext(static[:16], 60),
					))
					tb.sendNotifyTokenAssigned(
						t, src, c.PublicKey(), assigned, 60,
					)
				}
			}()

			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			got, err := c.RegisterOn(
				ctx, conn, tc.token, net.IPv4(127, 0, 0, 1), 12345,
			)
			a.NoError(err)
			a.Equal(tc.wantToken, got)
			src := <-srcCh
			a.Equal(local.Port, src.Port, "REGISTER left another socket")
			if tc.random {
				return
			}

			_, err = tb.conn.WriteToUDP(
				sealedPeerMatched(t, c.PublicKey(), 4242), src,
			)
			a.NoError(err)
			p, err := c.ReadNotify(ctx, conn)
			a.NoError(err)
			a.Equal(NotifyPeerMatched, p.Type)
			a.Equal(uint16(4242), p.Port)
		})
	}
}

// TestClient_ReadNotify_DropsOtherSources sends a NOTIFY that decrypts
// with the client's key from a socket other than the broker's, then
// one from the broker, and checks that only the broker's is returned.
func TestClient_ReadNotify_DropsOtherSources(t *testing.T) {
	a := require.New(t)
	tb := newTestBroker(t)
	c, err := NewClient(tb.addr.String())
	a.NoError(err)
	conn := punchSocket(t)
	local := conn.LocalAddr().(*net.UDPAddr)

	stranger(t, local, sealedPeerMatched(t, c.PublicKey(), 1111))
	_, err = tb.conn.WriteToUDP(sealedPeerMatched(t, c.PublicKey(), 2222), local)
	a.NoError(err)

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	p, err := c.ReadNotify(ctx, conn)
	a.NoError(err)
	a.Equal(uint16(2222), p.Port)
}

// TestClient_Listen_DropsOtherSources checks the same source filter on
// the deprecated Listen channel.
func TestClient_Listen_DropsOtherSources(t *testing.T) {
	a := require.New(t)
	tb := newTestBroker(t)
	c, err := NewClient(tb.addr.String())
	a.NoError(err)

	out, clientAddr, err := c.Listen(t.Context())
	a.NoError(err)
	stranger(t, clientAddr, sealedPeerMatched(t, c.PublicKey(), 1111))
	_, err = tb.conn.WriteToUDP(
		sealedPeerMatched(t, c.PublicKey(), 2222), clientAddr,
	)
	a.NoError(err)

	select {
	case p := <-out:
		a.Equal(uint16(2222), p.Port)
	case <-time.After(2 * time.Second):
		a.Fail("did not receive NOTIFY within 2s")
	}
}

// TestClient_ReadNotify_Context checks that ReadNotify gives up when
// its context ends and leaves the socket without a read deadline.
func TestClient_ReadNotify_Context(t *testing.T) {
	a := require.New(t)
	tb := newTestBroker(t)
	c, err := NewClient(tb.addr.String())
	a.NoError(err)
	conn := punchSocket(t)

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	_, err = c.ReadNotify(ctx, conn)
	a.ErrorIs(err, context.DeadlineExceeded)

	cctx, ccancel := context.WithCancel(t.Context())
	ccancel()
	_, err = c.ReadNotify(cctx, conn)
	a.ErrorIs(err, context.Canceled)

	// The deadline is cleared, so a later packet is still read.
	_, err = tb.conn.WriteToUDP(
		sealedPeerMatched(t, c.PublicKey(), 3333),
		conn.LocalAddr().(*net.UDPAddr),
	)
	a.NoError(err)
	p, err := c.ReadNotify(t.Context(), conn)
	a.NoError(err)
	a.Equal(uint16(3333), p.Port)
}
