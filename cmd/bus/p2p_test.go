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
	assert.Len(t, t1, 16)
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
