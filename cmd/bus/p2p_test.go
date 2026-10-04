package main

import (
	"bytes"
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

	"github.com/kamune-org/kamune/pkg/fingerprint"
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
	pkt, err := sealedNotify(plaintext, peerEphPub)
	a.NoError(err)
	_, err = b.conn.WriteToUDP(pkt, dst)
	a.NoError(err)
}

// sealedNotify returns a NOTIFY packet that carries plaintext to the
// peer whose broker key is peerEphPub.
func sealedNotify(plaintext, peerEphPub []byte) ([]byte, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	peerPub, err := ecdh.X25519().NewPublicKey(peerEphPub)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(peerPub)
	if err != nil {
		return nil, err
	}
	key := sha256.Sum256(shared)
	brokerEphPub := eph.PublicKey().Bytes()
	nonce, sealed := relaybroker.SealNotify(key[:], brokerEphPub, plaintext)
	switch plaintext[0] {
	case byte(relaybroker.NotifyPeerMatched):
		return relaybroker.BuildNotifyPeerMatched(
			brokerEphPub, nonce, sealed,
		), nil
	case byte(relaybroker.NotifyTokenAssigned):
		return relaybroker.BuildNotifyTokenAssigned(
			brokerEphPub, nonce, sealed,
		), nil
	}
	return nil, fmt.Errorf("unknown notify type %d", plaintext[0])
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

// brokerRegistration is a REGISTER that serveFakeBroker received: the
// token in its wire form, or the one it assigned, and the source.
type brokerRegistration struct {
	token []byte
	src   *net.UDPAddr
}

// serveFakeBroker answers every ECHO that fb receives, assigns a token to
// a random-mode REGISTER and reports each REGISTER on the returned
// channel, until fb is closed at the end of the test.
func serveFakeBroker(fb *fakeBroker) <-chan brokerRegistration {
	regs := make(chan brokerRegistration, 64)
	go func() {
		buf := make([]byte, 1500)
		for {
			n, src, err := fb.conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			pkt := buf[:n]
			if relaybroker.ParseEchoRequest(pkt) == nil {
				resp := relaybroker.BuildEchoResponse(src)
				_, _ = fb.conn.WriteToUDP(resp, src)
				continue
			}
			token, ephPub, _, _, err := relaybroker.ParseRegister(pkt)
			if err != nil {
				continue
			}
			token = bytes.Clone(token)
			if bytes.Equal(token, make([]byte, len(token))) {
				if _, err := rand.Read(token); err != nil {
					return
				}
				notify, err := sealedNotify(
					relaybroker.TokenAssignedPlaintext(token, 60), ephPub,
				)
				if err != nil {
					return
				}
				_, _ = fb.conn.WriteToUDP(notify, src)
			}
			regs <- brokerRegistration{token: token, src: src}
		}
	}()
	return regs
}

// nextRegistration returns the next REGISTER that serveFakeBroker saw.
func nextRegistration(
	t *testing.T, regs <-chan brokerRegistration,
) brokerRegistration {
	t.Helper()
	select {
	case r := <-regs:
		return r
	case <-time.After(testWait):
		t.Fatal("the broker got no REGISTER")
		return brokerRegistration{}
	}
}

// startTestP2PServer starts a p2p listener on a fake broker and makes it
// app's running P2P listener, as StartServer does, with token, or a
// random one when token is nil, for the peer whose key is peerKey. It
// returns the broker's address and the channel of the REGISTERs the
// broker gets, past the listener's own.
func startTestP2PServer(
	t *testing.T, app *App, token, peerKey []byte,
) (*p2pListener, string, <-chan brokerRegistration) {
	t.Helper()
	a := require.New(t)
	fb := newFakeBroker(t)
	regs := serveFakeBroker(fb)
	addr := fb.conn.LocalAddr().String()
	l, err := newP2PListener(
		app.brokerClient, addr, token, peerKey, "127.0.0.1:0",
	)
	a.NoError(err)
	t.Cleanup(func() { _ = l.Close() })
	own := nextRegistration(t, regs)
	a.Equal(l.Addr().Port, own.src.Port)
	mode := "random"
	if token != nil {
		mode = "static"
	}
	app.mu.Lock()
	app.p2pListener = l
	app.p2pTokens = append(app.p2pTokens, p2pToken{
		Token: l.Token(), Mode: mode,
	})
	app.mu.Unlock()
	return l, addr, regs
}

func TestGenerateP2PToken_RequiresP2PServer(t *testing.T) {
	a := require.New(t)
	app := newTestAppForP2P(t)
	_, err := app.GenerateP2PToken("127.0.0.1:1", "")
	a.ErrorIs(err, ErrNoP2PServer)

	_, addr, _ := startTestP2PServer(t, app, nil, nil)
	_, err = app.GenerateP2PToken("127.0.0.1:1", "")
	a.ErrorIs(err, ErrNoP2PServer, "a server on another broker")
	_, err = app.GenerateP2PToken(addr, "")
	a.NoError(err)
}

// TestGenerateP2PToken_RegistersOnPunchSocket checks that each generated
// token is registered from the p2p listener's punch socket, the address
// a matched peer is told to punch to, and that each random token is a
// new one.
func TestGenerateP2PToken_RegistersOnPunchSocket(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()
	var err error
	app.brokerClient, err = NewBrokerClient()
	a.NoError(err)
	l, addr, regs := startTestP2PServer(t, app, nil, nil)

	seen := map[string]bool{l.Token(): true}
	for range 2 {
		tok, err := app.GenerateP2PToken(addr, "")
		a.NoError(err)
		a.False(seen[tok], "a random token must be new")
		seen[tok] = true
		reg := nextRegistration(t, regs)
		a.Equal(tok, hex.EncodeToString(reg.token))
		a.Equal(l.Addr().Port, reg.src.Port)
	}

	peer := fingerprint.Base64(newTestPubKey(t))
	tok, err := app.GenerateP2PToken(addr, peer)
	a.NoError(err)
	raw, err := hex.DecodeString(tok)
	a.NoError(err)
	a.Len(raw, 32)
	reg := nextRegistration(t, regs)
	a.Equal(relaybroker.WireToken(raw), reg.token)
	a.Equal(l.Addr().Port, reg.src.Port)
	again, err := app.GenerateP2PToken(addr, peer)
	a.NoError(err)
	a.Equal(tok, again, "a peer's static token is the same")

	got := app.GetP2PTokens()
	a.Len(got, 4)
	a.Equal("static", got[3].Mode)
	a.Equal(peer, got[3].PeerPubB64)
}

// TestRemoveP2PToken_StopsRegistering checks that a removed token is no
// longer registered with the broker, whether it was generated or is the
// server's own token, and that the peer of a removed static token is
// turned away while no random token is registered.
func TestRemoveP2PToken_StopsRegistering(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()
	var err error
	app.brokerClient, err = NewBrokerClient()
	a.NoError(err)

	aliceKey, bobKey := newTestPubKey(t), newTestPubKey(t)
	own := bytes.Repeat([]byte{3}, 32)
	l, addr, regs := startTestP2PServer(t, app, own, aliceKey)
	bob := fingerprint.Base64(bobKey)
	tok, err := app.GenerateP2PToken(addr, bob)
	a.NoError(err)
	nextRegistration(t, regs)
	a.True(l.admitsPeer(bobKey))

	a.NoError(app.RemoveP2PToken(tok))
	a.False(l.admitsPeer(bobKey))
	a.True(l.admitsPeer(aliceKey))
	a.NoError(l.refreshRegistration())
	reg := nextRegistration(t, regs)
	a.Equal(relaybroker.WireToken(own), reg.token)
	// The next REGISTER is for a new token: the removed one is not sent.
	fresh, err := app.GenerateP2PToken(addr, "")
	a.NoError(err)
	reg = nextRegistration(t, regs)
	a.Equal(fresh, hex.EncodeToString(reg.token))
	// The listener cannot tell which token a peer matched on, so a
	// random token admits any peer, the removed token's included.
	a.True(l.admitsPeer(bobKey))

	a.NoError(app.RemoveP2PToken(hex.EncodeToString(own)))
	a.True(l.admitsPeer(aliceKey), "the random token admits any peer")
	a.NoError(app.RemoveP2PToken(fresh))
	a.Empty(l.liveTokens())
	a.False(l.admitsPeer(bobKey))
	a.False(l.admitsPeer(aliceKey), "no token is left to admit a peer")
	a.Empty(app.GetP2PTokens())
}

// TestGenerateP2PToken_RefusesPastCap checks that a P2P server keeps at
// most maxP2PTokens tokens, its own included, so that its refreshes stay
// within a broker's default REGISTER quota. A new token past the cap is
// refused and never sent, a peer's listed static token is still returned,
// and a removed token makes room for another.
func TestGenerateP2PToken_RefusesPastCap(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()
	var err error
	app.brokerClient, err = NewBrokerClient()
	a.NoError(err)
	l, addr, regs := startTestP2PServer(t, app, nil, nil)

	peer := fingerprint.Base64(newTestPubKey(t))
	static, err := app.GenerateP2PToken(addr, peer)
	a.NoError(err)
	for range maxP2PTokens - 2 {
		_, err := app.GenerateP2PToken(addr, "")
		a.NoError(err)
	}
	a.Len(app.GetP2PTokens(), maxP2PTokens)

	_, err = app.GenerateP2PToken(addr, "")
	a.ErrorIs(err, ErrTooManyP2PTokens)
	other := fingerprint.Base64(newTestPubKey(t))
	_, err = app.GenerateP2PToken(addr, other)
	a.ErrorIs(err, ErrTooManyP2PTokens)
	again, err := app.GenerateP2PToken(addr, peer)
	a.NoError(err)
	a.Equal(static, again, "a listed static token is returned")
	a.Len(app.GetP2PTokens(), maxP2PTokens)
	a.Len(l.liveTokens(), maxP2PTokens)

	// The listener sent a REGISTER for each generated token and sends one
	// for each listed token on a refresh, and none for a refused one.
	listed := make(map[string]bool)
	for _, pt := range app.GetP2PTokens() {
		raw, err := hex.DecodeString(pt.Token)
		a.NoError(err)
		listed[hex.EncodeToString(relaybroker.WireToken(raw))] = true
	}
	a.NoError(l.refreshRegistration())
	for range 2*maxP2PTokens - 1 {
		reg := hex.EncodeToString(nextRegistration(t, regs).token)
		a.True(listed[reg], "a refused token was registered: %s", reg)
	}

	a.NoError(app.RemoveP2PToken(static))
	_, err = app.GenerateP2PToken(addr, "")
	a.NoError(err, "a removed token makes room for another")
	a.Len(app.GetP2PTokens(), maxP2PTokens)
	a.Len(l.liveTokens(), maxP2PTokens)
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
	app.p2pTokens = []p2pToken{{Token: "deadbeef"}}
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

// TestWaitMatch_TokenWireForm checks that WaitMatch accepts a
// PEER_MATCHED that carries the broker's 16-byte wire form of its token,
// as the broker sends it for a 32-byte static token, and skips one for
// another token.
func TestWaitMatch_TokenWireForm(t *testing.T) {
	static, err := relayconn.TokenFromKeys(
		ed25519.PublicKey(make([]byte, 32)),
		ed25519.PublicKey(bytes.Repeat([]byte{1}, 32)),
	)
	require.New(t).NoError(err)
	random := bytes.Repeat([]byte{7}, 16)

	tests := []struct {
		name  string
		token []byte
	}{
		{name: "static 32-byte token", token: static},
		{name: "random 16-byte token", token: random},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			fb := newFakeBroker(t)
			otherEph, err := ecdh.X25519().GenerateKey(rand.Reader)
			a.NoError(err)
			otherIP := net.IPv4(192, 0, 2, 1)

			go func() {
				_, src := fb.readOne(t, 2*time.Second)
				fb.respondEcho(t, src)
				pkt, src := fb.readOne(t, 2*time.Second)
				wire, ephPub, _, _, err := relaybroker.ParseRegister(pkt)
				if err != nil {
					return
				}
				// A match for another token comes first and must
				// be skipped.
				other := bytes.Repeat([]byte{9}, 16)
				sendNotify(t, fb, relaybroker.PeerMatchedPlaintext(
					other, otherEph.PublicKey().Bytes(), otherIP, 1111,
				), src, ephPub)
				sendNotify(t, fb, relaybroker.PeerMatchedPlaintext(
					wire, otherEph.PublicKey().Bytes(), otherIP, 2222,
				), src, ephPub)
			}()

			bc, err := NewBrokerClient()
			a.NoError(err)
			ctx, cancel := context.WithTimeout(
				context.Background(), 10*time.Second,
			)
			defer cancel()
			conn, payload, err := bc.WaitMatch(
				ctx, fb.conn.LocalAddr().String(), tt.token,
			)
			a.NoError(err)
			defer conn.Close()
			a.Equal(uint16(2222), payload.Port)
			a.True(relaybroker.TokenMatches(payload.Token, tt.token))
		})
	}
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
