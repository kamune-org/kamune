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
	a := require.New(t)
	addr, err := net.ResolveUDPAddr("udp4", "127.0.0.1:0")
	a.NoError(err)
	conn, err := net.ListenUDP("udp4", addr)
	a.NoError(err)
	t.Cleanup(func() { _ = conn.Close() })
	return &fakeBroker{conn: conn}
}

func (b *fakeBroker) readOne(
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

func (b *fakeBroker) respondEcho(t *testing.T, src *net.UDPAddr) {
	t.Helper()
	a := require.New(t)
	addr := &net.UDPAddr{IP: src.IP, Port: src.Port}
	resp := relaybroker.BuildEchoResponse(addr)
	_, err := b.conn.WriteToUDP(resp, src)
	a.NoError(err)
}

func sendNotify(
	t *testing.T, b *fakeBroker, plaintext []byte,
	dst *net.UDPAddr, peerEphPub []byte,
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
	nonce, sealed := relaybroker.SealNotify(key[:], brokerEphPub, plaintext)
	var pkt []byte
	switch plaintext[0] {
	case byte(relaybroker.NotifyPeerMatched):
		pkt = relaybroker.BuildNotifyPeerMatched(brokerEphPub, nonce, sealed)
	case byte(relaybroker.NotifyTokenAssigned):
		pkt = relaybroker.BuildNotifyTokenAssigned(brokerEphPub, nonce, sealed)
	}
	_, err = b.conn.WriteToUDP(pkt, dst)
	a.NoError(err)
}

// ---------------------------------------------------------------------------
// BrokerClient tests
// ---------------------------------------------------------------------------

func TestBrokerClient_StableKey(t *testing.T) {
	a := require.New(t)
	bc, err := NewBrokerClient()
	a.NoError(err)

	pub1 := bc.PublicKey()
	pub2 := bc.PublicKey()
	a.Equal(pub1, pub2)

	// Mutating the returned slice must not affect the broker.
	pub1[0] = 0xff
	a.NotEqual(pub1[0], bc.PublicKey()[0])
}

func TestBrokerClient_LazyClientCaches(t *testing.T) {
	a := require.New(t)
	bc, err := NewBrokerClient()
	a.NoError(err)

	fb := newFakeBroker(t)
	addr := fb.conn.LocalAddr().String()

	c1, err := bc.Client(addr)
	a.NoError(err)
	c2, err := bc.Client(addr)
	a.NoError(err)
	a.Same(c1, c2)
}

func TestBrokerClient_NewClientForNewAddress(t *testing.T) {
	a := require.New(t)
	bc, err := NewBrokerClient()
	a.NoError(err)

	fb1 := newFakeBroker(t)
	fb2 := newFakeBroker(t)

	c1, err := bc.Client(fb1.conn.LocalAddr().String())
	a.NoError(err)
	c2, err := bc.Client(fb2.conn.LocalAddr().String())
	a.NoError(err)
	a.NotSame(c1, c2)
}

// ---------------------------------------------------------------------------
// p2pToken lifecycle tests
// ---------------------------------------------------------------------------

func newTestAppForP2P(t *testing.T) *App {
	t.Helper()
	a := require.New(t)
	app := &App{
		ctx:           context.Background(),
		mu:            sync.RWMutex{},
		peers:         make([]PeerInfo, 0),
		verifRequests: make(map[int64]*pendingVerification),
	}
	var err error
	app.brokerClient, err = NewBrokerClient()
	a.NoError(err)
	app.p2pTokens = make([]p2pToken, 0)
	return app
}

func TestGenerateP2PToken_AssignsAndAppends(t *testing.T) {
	a := require.New(t)
	app := newTestAppForP2P(t)
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
		a.NoError(err)
		token, peerEphPub, _, _, err := relaybroker.ParseRegister(buf[:n])
		a.NoError(err)
		plaintext := relaybroker.TokenAssignedPlaintext(token, 60)
		sendNotify(t, fb, plaintext, src2, peerEphPub)
		done <- token
	}()

	token, err := app.GenerateP2PToken(addr, "")
	a.NoError(err)
	expected := <-done
	a.Equal(hex.EncodeToString(expected), token)

	got := app.GetP2PTokens()
	a.Len(got, 1)
	a.Equal(hex.EncodeToString(expected), got[0].Token)
	a.False(got[0].Consumed)
	a.NotZero(got[0].ExpiresAt)
}

func TestGenerateP2PToken_EmptyAddress(t *testing.T) {
	a := require.New(t)
	app := newTestAppForP2P(t)
	_, err := app.GenerateP2PToken("", "")
	a.Error(err)
}

func TestRemoveP2PToken(t *testing.T) {
	a := require.New(t)
	app := newTestAppForP2P(t)
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	app.p2pTokens = []p2pToken{{Token: "deadbeef", cancel: cancel}}
	err := app.RemoveP2PToken("deadbeef")
	a.NoError(err)
	a.Empty(app.GetP2PTokens())
}

func TestRemoveP2PToken_NotFound(t *testing.T) {
	a := require.New(t)
	app := newTestAppForP2P(t)
	err := app.RemoveP2PToken("nope")
	a.Error(err)
}

func TestGetP2PTokens_DefensiveCopy(t *testing.T) {
	a := require.New(t)
	app := newTestAppForP2P(t)
	app.p2pTokens = []p2pToken{{Token: "abc"}}
	got := app.GetP2PTokens()
	a.Len(got, 1)
	got[0].Token = "mutated"
	a.Equal("abc", app.GetP2PTokens()[0].Token)
}

// ---------------------------------------------------------------------------
// Static-token path tests
// ---------------------------------------------------------------------------

func TestParsePeerPubB64ToRaw_RoundTrip(t *testing.T) {
	a := require.New(t)
	raw := ed25519.PublicKey(make([]byte, 32))
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	pkix := mustPKIXForRaw(t, raw)
	b64 := base64.RawURLEncoding.EncodeToString(pkix)

	got, err := parsePeerPubB64ToRaw(b64)
	a.NoError(err)
	a.Equal([]byte(raw), []byte(got))
}

func TestParsePeerPubB64ToRaw_RejectsInvalid(t *testing.T) {
	a := require.New(t)
	_, err := parsePeerPubB64ToRaw("not-base64!")
	a.Error(err)

	// 16 bytes → 22 b64 chars, neither 43 nor 59 — rejected by
	// decodePeerPubKey before we get to PKIX parsing.
	short := base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	_, err = parsePeerPubB64ToRaw(short)
	a.Error(err)
}

func TestTokenFromKeysIsOrderIndependent(t *testing.T) {
	a := require.New(t)
	// The bus and the listener/dialer must agree on the token even when
	// they pass keys in different order.
	alice := ed25519.PublicKey(make([]byte, 32))
	bob := ed25519.PublicKey(make([]byte, 32))
	alice[0] = 0x01
	bob[0] = 0x02

	t1, err := relayconn.TokenFromKeys(alice, bob)
	a.NoError(err)
	t2, err := relayconn.TokenFromKeys(bob, alice)
	a.NoError(err)
	a.Equal(t1, t2)
	a.Len(t1, 32)
}

// ---------------------------------------------------------------------------
// RegisterP2PDialer tests
// ---------------------------------------------------------------------------

func TestRegisterP2PDialer_RequiresPeerOrToken(t *testing.T) {
	a := require.New(t)
	app := newTestAppForP2P(t)
	_, _, err := app.RegisterP2PDialer("127.0.0.1:1", "", "")
	a.Error(err)
}

func TestRegisterP2PDialer_RejectsBoth(t *testing.T) {
	a := require.New(t)
	app := newTestAppForP2P(t)
	_, _, err := app.RegisterP2PDialer("127.0.0.1:1", "abc", "deadbeef")
	a.Error(err)
}

func TestRegisterP2PDialer_EmptyAddress(t *testing.T) {
	a := require.New(t)
	app := newTestAppForP2P(t)
	_, _, err := app.RegisterP2PDialer("", "abc", "")
	a.Error(err)
}

// mustPKIXForRaw encodes an ed25519 public key in PKIX form.
func mustPKIXForRaw(t *testing.T, raw ed25519.PublicKey) []byte {
	t.Helper()
	a := require.New(t)
	pkix, err := x509.MarshalPKIXPublicKey(raw)
	a.NoError(err)
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
	a := require.New(t)
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
		a.NoError(err)
		token, dialerEphPub, _, _, err := relaybroker.ParseRegister(buf[:n])
		a.NoError(err)
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
	a := require.New(t)
	fb := newFakeBroker(t)
	addr := fb.conn.LocalAddr().String()

	otherEph, err := ecdh.X25519().GenerateKey(rand.Reader)
	a.NoError(err)
	const otherPort = uint16(54321)
	otherIP := net.IPv4(192, 0, 2, 1)
	runFakePeerMatchedBroker(
		t, fb, otherEph.PublicKey().Bytes(), otherIP, otherPort,
	)

	bc, err := NewBrokerClient()
	a.NoError(err)

	ctx, cancel := context.WithTimeout(
		context.Background(), 2*time.Second,
	)
	defer cancel()

	token := make([]byte, 16)
	for i := range token {
		token[i] = byte(i + 1)
	}
	punchConn, payload, err := bc.WaitMatch(ctx, addr, token)
	a.NoError(err)
	defer punchConn.Close()
	a.Equal(relaybroker.NotifyPeerMatched, payload.Type)
	a.Equal(otherEph.PublicKey().Bytes(), payload.OtherPeerEphPub)
	a.Equal("192.0.2.1", payload.IP.String())
	a.Equal(otherPort, payload.Port)
}

// TestWaitMatch_ContextCancel verifies that WaitMatch exits with the
// context's error when ctx is cancelled before a NOTIFY arrives.
func TestWaitMatch_ContextCancel(t *testing.T) {
	a := require.New(t)
	fb := newFakeBroker(t)
	addr := fb.conn.LocalAddr().String()

	bc, err := NewBrokerClient()
	a.NoError(err)

	// Don't run the broker goroutine — no ECHO response, so WaitMatch
	// will time out or fail.
	ctx, cancel := context.WithTimeout(
		context.Background(), 300*time.Millisecond,
	)
	defer cancel()

	token := make([]byte, 16)
	_, _, err = bc.WaitMatch(ctx, addr, token)
	a.Error(err)
}

// TestHolePunch_HappyPath verifies that HolePunch returns a KCP session
// immediately (no reachability wait). The session is in client mode and
// not yet connected; the kamune handshake drives the KCP-level connection.
func TestHolePunch_HappyPath(t *testing.T) {
	a := require.New(t)
	punchAddr, err := net.ResolveUDPAddr(
		"udp4", "127.0.0.1:0",
	)
	a.NoError(err)
	punchConn, err := net.ListenUDP("udp4", punchAddr)
	a.NoError(err)
	defer punchConn.Close()

	bc, err := NewBrokerClient()
	a.NoError(err)

	// Peer UDP socket — just to have a valid target address.
	peerAddr, err := net.ResolveUDPAddr("udp4", "127.0.0.1:0")
	a.NoError(err)
	peerUDP, err := net.ListenUDP("udp4", peerAddr)
	a.NoError(err)
	defer peerUDP.Close()

	// HolePunch returns immediately with a kcp session.
	sess, err := bc.HolePunch(
		context.Background(), punchConn,
		peerUDP.LocalAddr().(*net.UDPAddr).IP,
		uint16(peerUDP.LocalAddr().(*net.UDPAddr).Port), 0,
	)
	a.NoError(err)
	a.NotNil(sess)
	defer sess.Close()

	// The session is bound to the punch socket.
	a.Equal(punchConn.LocalAddr().String(), sess.LocalAddr().String())
	a.Equal(peerUDP.LocalAddr().(*net.UDPAddr).String(), sess.RemoteAddr().String())
}

// TestHolePunch_Failure verifies that ErrHolePunchFailed is a valid
// sentinel. HolePunch itself no longer fails for unreachable peers
// (kcp.NewConn2 creates a session immediately); failure is surfaced
// by the kamune handshake's timeout.
func TestHolePunch_Failure(t *testing.T) {
	a := require.New(t)
	// The sentinel is usable as an error value.
	a.Error(ErrHolePunchFailed)
	a.True(errors.Is(fmt.Errorf("%w: timeout", ErrHolePunchFailed), ErrHolePunchFailed))
}

// TestParseEchoResponse verifies the bus's echo response parser handles
// the broker's `ip:port\0` format.
func TestParseEchoResponse(t *testing.T) {
	a := require.New(t)
	ip, port, err := parseEchoResponse(
		append([]byte("192.0.2.1:54321"), 0),
	)
	a.NoError(err)
	a.Equal("192.0.2.1", ip.String())
	a.Equal(uint16(54321), port)

	// No trailing null — parser should still work (parses until end).
	ip, port, err = parseEchoResponse([]byte("10.0.0.1:8080"))
	a.NoError(err)
	a.Equal("10.0.0.1", ip.String())
	a.Equal(uint16(8080), port)
}
