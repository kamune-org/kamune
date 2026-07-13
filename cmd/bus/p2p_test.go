package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/pkg/relayconn"
	relaybroker "github.com/kamune-org/kamune/pkg/relayconn/broker"
)

// fakeBroker is a minimal UDP test broker that answers ECHO and REGISTER.
// It mirrors the testBroker in pkg/relayconn/broker but lives in the bus
// package since it needs the bus's App type.
type fakeBroker struct {
	conn *net.UDPConn
}

func newFakeBroker(t *testing.T) *fakeBroker {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	conn, err := net.ListenUDP("udp4", addr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return &fakeBroker{conn: conn}
}

func (b *fakeBroker) readOne(
	t *testing.T, timeout time.Duration,
) ([]byte, *net.UDPAddr) {
	t.Helper()
	_ = b.conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1500)
	n, src, err := b.conn.ReadFromUDP(buf)
	require.NoError(t, err)
	return buf[:n], src
}

func (b *fakeBroker) respondEcho(t *testing.T, src *net.UDPAddr) {
	t.Helper()
	addr := &net.UDPAddr{IP: src.IP, Port: src.Port}
	resp := relaybroker.BuildEchoResponse(addr)
	_, err := b.conn.WriteToUDP(resp, src)
	require.NoError(t, err)
}

func (b *fakeBroker) respondAssignedToken(
	t *testing.T, src *net.UDPAddr, peerEphPub []byte,
) []byte {
	t.Helper()
	token := make([]byte, 16)
	for i := range token {
		token[i] = byte(i + 1)
	}
	plaintext := relaybroker.TokenAssignedPlaintext(token, 60)
	sendNotify(t, b, plaintext, src, peerEphPub)
	return token
}

func sendNotify(
	t *testing.T, b *fakeBroker, plaintext []byte,
	dst *net.UDPAddr, peerEphPub []byte,
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
	nonce, sealed := relaybroker.SealNotify(key[:], brokerEphPub, plaintext)
	var pkt []byte
	switch plaintext[0] {
	case byte(relaybroker.NotifyPeerMatched):
		pkt = relaybroker.BuildNotifyPeerMatched(brokerEphPub, nonce, sealed)
	case byte(relaybroker.NotifyTokenAssigned):
		pkt = relaybroker.BuildNotifyTokenAssigned(brokerEphPub, nonce, sealed)
	}
	_, err = b.conn.WriteToUDP(pkt, dst)
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// BrokerClient tests
// ---------------------------------------------------------------------------

func TestBrokerClient_StableKey(t *testing.T) {
	bc, err := NewBrokerClient()
	require.NoError(t, err)

	pub1 := bc.PublicKey()
	pub2 := bc.PublicKey()
	assert.Equal(t, pub1, pub2)

	// Mutating the returned slice must not affect the broker.
	pub1[0] = 0xff
	assert.NotEqual(t, pub1[0], bc.PublicKey()[0])
}

func TestBrokerClient_LazyClientCaches(t *testing.T) {
	bc, err := NewBrokerClient()
	require.NoError(t, err)

	fb := newFakeBroker(t)
	addr := fb.conn.LocalAddr().String()

	c1, err := bc.Client(addr)
	require.NoError(t, err)
	c2, err := bc.Client(addr)
	require.NoError(t, err)
	assert.Same(t, c1, c2)
}

func TestBrokerClient_NewClientForNewAddress(t *testing.T) {
	bc, err := NewBrokerClient()
	require.NoError(t, err)

	fb1 := newFakeBroker(t)
	fb2 := newFakeBroker(t)

	c1, err := bc.Client(fb1.conn.LocalAddr().String())
	require.NoError(t, err)
	c2, err := bc.Client(fb2.conn.LocalAddr().String())
	require.NoError(t, err)
	assert.NotSame(t, c1, c2)
}

// ---------------------------------------------------------------------------
// p2pToken lifecycle tests
// ---------------------------------------------------------------------------

func newTestAppForP2P(t *testing.T) *App {
	t.Helper()
	a := &App{
		ctx:           context.Background(),
		mu:            sync.RWMutex{},
		peers:         make([]PeerInfo, 0),
		verifRequests: make(map[int64]*pendingVerification),
	}
	var err error
	a.brokerClient, err = NewBrokerClient()
	require.NoError(t, err)
	a.p2pTokens = make([]p2pToken, 0)
	return a
}

func TestGenerateP2PToken_AssignsAndAppends(t *testing.T) {
	a := newTestAppForP2P(t)
	fb := newFakeBroker(t)
	addr := fb.conn.LocalAddr().String()

	done := make(chan []byte, 1)
	go func() {
		// ECHO request from the client.
		_, src1 := fb.readOne(t, 2*time.Second)
		fb.respondEcho(t, src1)
		// REGISTER packet — read it, parse the X25519 pub out, send back
		// a NOTIFY(TOKEN_ASSIGNED).
		buf := make([]byte, 1500)
		_ = fb.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, src2, err := fb.conn.ReadFromUDP(buf)
		require.NoError(t, err)
		token, peerEphPub, _, _, err := relaybroker.ParseRegister(buf[:n])
		require.NoError(t, err)
		plaintext := relaybroker.TokenAssignedPlaintext(token, 60)
		sendNotify(t, fb, plaintext, src2, peerEphPub)
		done <- token
	}()

	token, err := a.GenerateP2PToken(addr, "")
	require.NoError(t, err)
	expected := <-done
	assert.Equal(t, hex.EncodeToString(expected), token)

	got := a.GetP2PTokens()
	require.Len(t, got, 1)
	assert.Equal(t, hex.EncodeToString(expected), got[0].Token)
	assert.False(t, got[0].Consumed)
	assert.NotZero(t, got[0].ExpiresAt)
}

func TestGenerateP2PToken_EmptyAddress(t *testing.T) {
	a := newTestAppForP2P(t)
	_, err := a.GenerateP2PToken("", "")
	assert.Error(t, err)
}

func TestRemoveP2PToken(t *testing.T) {
	a := newTestAppForP2P(t)
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.p2pTokens = []p2pToken{{Token: "deadbeef", cancel: cancel}}
	err := a.RemoveP2PToken("deadbeef")
	require.NoError(t, err)
	assert.Empty(t, a.GetP2PTokens())
}

func TestRemoveP2PToken_NotFound(t *testing.T) {
	a := newTestAppForP2P(t)
	err := a.RemoveP2PToken("nope")
	assert.Error(t, err)
}

func TestGetP2PTokens_DefensiveCopy(t *testing.T) {
	a := newTestAppForP2P(t)
	a.p2pTokens = []p2pToken{{Token: "abc"}}
	got := a.GetP2PTokens()
	require.Len(t, got, 1)
	got[0].Token = "mutated"
	assert.Equal(t, "abc", a.GetP2PTokens()[0].Token)
}

// ---------------------------------------------------------------------------
// Static-token path tests
// ---------------------------------------------------------------------------

func TestParsePeerPubB64ToRaw_RoundTrip(t *testing.T) {
	raw := ed25519.PublicKey(make([]byte, 32))
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	pkix := mustPKIXForRaw(t, raw)
	b64 := base64.RawURLEncoding.EncodeToString(pkix)

	got, err := parsePeerPubB64ToRaw(b64)
	require.NoError(t, err)
	assert.Equal(t, []byte(raw), []byte(got))
}

func TestParsePeerPubB64ToRaw_RejectsInvalid(t *testing.T) {
	_, err := parsePeerPubB64ToRaw("not-base64!")
	assert.Error(t, err)

	// 16 bytes → 22 b64 chars, neither 43 nor 59 — rejected by
	// decodePeerPubKey before we get to PKIX parsing.
	short := base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	_, err = parsePeerPubB64ToRaw(short)
	assert.Error(t, err)
}

func TestTokenFromKeysIsOrderIndependent(t *testing.T) {
	// The bus and the listener/dialer must agree on the token even when
	// they pass keys in different order.
	a := ed25519.PublicKey(make([]byte, 32))
	b := ed25519.PublicKey(make([]byte, 32))
	a[0] = 0x01
	b[0] = 0x02

	t1, err := relayconn.TokenFromKeys(a, b)
	require.NoError(t, err)
	t2, err := relayconn.TokenFromKeys(b, a)
	require.NoError(t, err)
	assert.Equal(t, t1, t2)
	assert.Len(t, t1, 32)
}

// ---------------------------------------------------------------------------
// RegisterP2PDialer tests
// ---------------------------------------------------------------------------

func TestRegisterP2PDialer_RequiresPeerOrToken(t *testing.T) {
	a := newTestAppForP2P(t)
	_, _, err := a.RegisterP2PDialer("127.0.0.1:1", "", "")
	assert.Error(t, err)
}

func TestRegisterP2PDialer_RejectsBoth(t *testing.T) {
	a := newTestAppForP2P(t)
	_, _, err := a.RegisterP2PDialer("127.0.0.1:1", "abc", "deadbeef")
	assert.Error(t, err)
}

func TestRegisterP2PDialer_EmptyAddress(t *testing.T) {
	a := newTestAppForP2P(t)
	_, _, err := a.RegisterP2PDialer("", "abc", "")
	assert.Error(t, err)
}

// mustPKIXForRaw encodes an ed25519 public key in PKIX form.
func mustPKIXForRaw(t *testing.T, raw ed25519.PublicKey) []byte {
	t.Helper()
	pkix, err := x509.MarshalPKIXPublicKey(raw)
	require.NoError(t, err)
	return pkix
}

// ---------------------------------------------------------------------------
// WaitMatch / HolePunch tests
// ---------------------------------------------------------------------------

// runFakePeerMatchedBroker runs a fake broker in a goroutine that responds
// to ECHO and REGISTER, then sends a NOTIFY(PEER_MATCHED) carrying the
// supplied peer coordinates. The token from the dialer's REGISTER packet
// is echoed back in the NOTIFY (matching production broker behavior).
func runFakePeerMatchedBroker(
	t *testing.T, fb *fakeBroker,
	otherEphPub []byte, otherIP net.IP, otherPort uint16,
) {
	t.Helper()
	go func() {
		// 1. ECHO from the dialer — read it, send back the source address.
		_, src1 := fb.readOne(t, 2*time.Second)
		fb.respondEcho(t, src1)
		// 2. REGISTER from the dialer — read it, use the dialer's token
		//    in the PEER_MATCHED NOTIFY (matches production where the
		//    broker echoes the matched token).
		buf := make([]byte, 1500)
		_ = fb.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, src2, err := fb.conn.ReadFromUDP(buf)
		require.NoError(t, err)
		token, dialerEphPub, _, _, err := relaybroker.ParseRegister(buf[:n])
		require.NoError(t, err)
		plaintext := relaybroker.PeerMatchedPlaintext(
			token, otherEphPub, otherIP, otherPort,
		)
		sendNotify(t, fb, plaintext, src2, dialerEphPub)
	}()
}

// TestWaitMatch_ReceivesPeerMatched verifies that WaitMatch opens a punch
// socket, registers on the broker, and returns the payload from the
// NOTIFY(PEER_MATCHED) the broker sends back.
func TestWaitMatch_ReceivesPeerMatched(t *testing.T) {
	fb := newFakeBroker(t)
	addr := fb.conn.LocalAddr().String()

	otherEph, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	const otherPort = uint16(54321)
	otherIP := net.IPv4(192, 0, 2, 1)
	runFakePeerMatchedBroker(
		t, fb, otherEph.PublicKey().Bytes(), otherIP, otherPort,
	)

	bc, err := NewBrokerClient()
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(
		context.Background(), 2*time.Second,
	)
	defer cancel()

	token := make([]byte, 16)
	for i := range token {
		token[i] = byte(i + 1)
	}
	punchConn, payload, err := bc.WaitMatch(ctx, addr, token)
	require.NoError(t, err)
	defer punchConn.Close()
	assert.Equal(t, relaybroker.NotifyPeerMatched, payload.Type)
	assert.Equal(t, otherEph.PublicKey().Bytes(), payload.OtherPeerEphPub)
	assert.Equal(t, "192.0.2.1", payload.IP.String())
	assert.Equal(t, otherPort, payload.Port)
}

// TestWaitMatch_ContextCancel verifies that WaitMatch exits with the
// context's error when ctx is cancelled before a NOTIFY arrives.
func TestWaitMatch_ContextCancel(t *testing.T) {
	fb := newFakeBroker(t)
	addr := fb.conn.LocalAddr().String()

	bc, err := NewBrokerClient()
	require.NoError(t, err)

	// Don't run the broker goroutine — no ECHO response, so WaitMatch
	// will time out or fail.
	ctx, cancel := context.WithTimeout(
		context.Background(), 300*time.Millisecond,
	)
	defer cancel()

	token := make([]byte, 16)
	_, _, err = bc.WaitMatch(ctx, addr, token)
	assert.Error(t, err)
}

// TestHolePunch_HappyPath verifies that HolePunch returns a KCP session
// immediately (no reachability wait). The session is in client mode and
// not yet connected; the kamune handshake drives the KCP-level connection.
func TestHolePunch_HappyPath(t *testing.T) {
	punchAddr, err := net.ResolveUDPAddr(
		"udp4", "127.0.0.1:0",
	)
	require.NoError(t, err)
	punchConn, err := net.ListenUDP("udp4", punchAddr)
	require.NoError(t, err)
	defer punchConn.Close()

	bc, err := NewBrokerClient()
	require.NoError(t, err)

	// Peer UDP socket — just to have a valid target address.
	peerAddr, err := net.ResolveUDPAddr("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	peerUDP, err := net.ListenUDP("udp4", peerAddr)
	require.NoError(t, err)
	defer peerUDP.Close()

	// HolePunch returns immediately with a kcp session.
	sess, err := bc.HolePunch(
		context.Background(), punchConn,
		peerUDP.LocalAddr().(*net.UDPAddr).IP,
		uint16(peerUDP.LocalAddr().(*net.UDPAddr).Port), 0,
	)
	require.NoError(t, err)
	require.NotNil(t, sess)
	defer sess.Close()

	// The session is bound to the punch socket.
	assert.Equal(t, punchConn.LocalAddr().String(),
		sess.LocalAddr().String())
	assert.Equal(t,
		peerUDP.LocalAddr().(*net.UDPAddr).String(),
		sess.RemoteAddr().String(),
	)
}

// TestHolePunch_Failure verifies that ErrHolePunchFailed is a valid
// sentinel. HolePunch itself no longer fails for unreachable peers
// (kcp.NewConn2 creates a session immediately); failure is surfaced
// by the kamune handshake's timeout.
func TestHolePunch_Failure(t *testing.T) {
	// The sentinel is usable as an error value.
	assert.Error(t, ErrHolePunchFailed)
	assert.True(t, errors.Is(fmt.Errorf("%w: timeout", ErrHolePunchFailed),
		ErrHolePunchFailed))
}

// TestParseEchoResponse verifies the bus's echo response parser handles
// the broker's `ip:port\0` format.
func TestParseEchoResponse(t *testing.T) {
	ip, port, err := parseEchoResponse(
		append([]byte("192.0.2.1:54321"), 0),
	)
	require.NoError(t, err)
	assert.Equal(t, "192.0.2.1", ip.String())
	assert.Equal(t, uint16(54321), port)

	// No trailing null — parser should still work (parses until end).
	ip, port, err = parseEchoResponse([]byte("10.0.0.1:8080"))
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.1", ip.String())
	assert.Equal(t, uint16(8080), port)
}
