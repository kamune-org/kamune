package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/pkg/fingerprint"
	relaybroker "github.com/kamune-org/kamune/pkg/relayconn/broker"
)

// fakeBroker answers STUN_ECHO requests and records the wire token of
// each REGISTER. When match is set, it answers each REGISTER with a
// PEER_MATCHED for the registered token, as the broker does once the
// other peer has registered it; otherwise it ignores REGISTERs, as when
// no peer holds the token.
type fakeBroker struct {
	conn  *net.UDPConn
	match bool
	peer  *net.UDPAddr
	// noEcho makes the broker drop STUN_ECHO requests.
	noEcho atomic.Bool

	mu sync.Mutex
	// registered holds the wire token of each REGISTER, keys the X25519
	// key it carried and sources the address it came from.
	registered [][]byte
	keys       [][]byte
	sources    []string
	changed    chan struct{}
}

func newFakeBroker(t *testing.T, match bool) *fakeBroker {
	a := require.New(t)
	conn, err := net.ListenUDP(
		"udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
	)
	a.NoError(err)
	b := &fakeBroker{
		conn:    conn,
		match:   match,
		peer:    &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9},
		changed: make(chan struct{}, 1),
	}
	t.Cleanup(func() { _ = conn.Close() })
	go b.serve()
	return b
}

func (b *fakeBroker) addr() string { return b.conn.LocalAddr().String() }

func (b *fakeBroker) serve() {
	buf := make([]byte, 1500)
	for {
		n, src, err := b.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		pkt := buf[:n]
		if relaybroker.ParseEchoRequest(pkt) == nil {
			if !b.noEcho.Load() {
				resp := relaybroker.BuildEchoResponse(src)
				_, _ = b.conn.WriteToUDP(resp, src)
			}
			continue
		}
		token, peerEphPub, _, _, err := relaybroker.ParseRegister(pkt)
		if err != nil {
			continue
		}
		b.mu.Lock()
		b.registered = append(b.registered, slices.Clone(token))
		b.keys = append(b.keys, slices.Clone(peerEphPub))
		b.sources = append(b.sources, src.String())
		b.mu.Unlock()
		select {
		case b.changed <- struct{}{}:
		default:
		}
		if !b.match {
			continue
		}
		_, _ = b.conn.WriteToUDP(b.peerMatched(token, peerEphPub), src)
	}
}

// registrations returns the wire tokens of the REGISTERs received so
// far.
func (b *fakeBroker) registrations() [][]byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.registered)
}

// keysFor returns the distinct X25519 keys that the REGISTERs of token
// carried.
func (b *fakeBroker) keysFor(token []byte) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var keys []string
	for i, r := range b.registered {
		key := hex.EncodeToString(b.keys[i])
		if relaybroker.TokenMatches(r, token) && !slices.Contains(keys, key) {
			keys = append(keys, key)
		}
	}
	return keys
}

// sourcesFor returns the distinct addresses that the REGISTERs of token
// came from.
func (b *fakeBroker) sourcesFor(token []byte) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var sources []string
	for i, r := range b.registered {
		src := b.sources[i]
		if relaybroker.TokenMatches(r, token) &&
			!slices.Contains(sources, src) {
			sources = append(sources, src)
		}
	}
	return sources
}

// waitRegistered waits for a REGISTER of token and returns the wire
// tokens of the REGISTERs received until then.
func (b *fakeBroker) waitRegistered(t *testing.T, token []byte) [][]byte {
	t.Helper()
	deadline := time.After(testEventTimeout)
	for {
		got := b.registrations()
		if slices.ContainsFunc(got, func(r []byte) bool {
			return relaybroker.TokenMatches(r, token)
		}) {
			return got
		}
		select {
		case <-b.changed:
		case <-deadline:
			t.Fatalf("broker got no REGISTER for %x", token)
		}
	}
}

// peerMatched returns a PEER_MATCHED for the wire token token, sealed to
// the registering peer's key peerEphPub.
func (b *fakeBroker) peerMatched(token, peerEphPub []byte) []byte {
	return sealPeerMatched(token, peerEphPub, b.peer, make([]byte, 32))
}

// sealPeerMatched returns a PEER_MATCHED for the wire token token, sealed
// to the key to, that names peer and its key peerKey.
func sealPeerMatched(
	token, to []byte, peer *net.UDPAddr, peerKey []byte,
) []byte {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	toPub, err := ecdh.X25519().NewPublicKey(to)
	if err != nil {
		panic(err)
	}
	shared, err := eph.ECDH(toPub)
	if err != nil {
		panic(err)
	}
	key := sha256.Sum256(shared)
	brokerEphPub := eph.PublicKey().Bytes()
	plaintext := relaybroker.PeerMatchedPlaintext(
		token, peerKey, peer.IP, uint16(peer.Port),
	)
	nonce, sealed := relaybroker.SealNotify(key[:], brokerEphPub, plaintext)
	return relaybroker.BuildNotifyPeerMatched(brokerEphPub, nonce, sealed)
}

func TestWaitMatchAcceptsStaticToken(t *testing.T) {
	a := require.New(t)
	broker := newFakeBroker(t, true)
	client, err := NewBrokerClient()
	a.NoError(err)
	// A static token, as relayconn.TokenFromKeys derives, is 32 bytes;
	// the broker echoes its 16-byte wire form.
	token := []byte(strings.Repeat("s", 32))

	ctx, cancel := context.WithTimeout(context.Background(), testEventTimeout)
	defer cancel()
	conn, payload, err := client.WaitMatch(ctx, broker.addr(), token)
	a.NoError(err)
	defer conn.Close()
	a.Equal(relaybroker.NotifyPeerMatched, payload.Type)
	a.True(payload.IP.Equal(broker.peer.IP))
	a.Equal(uint16(broker.peer.Port), payload.Port)
}

func TestWaitMatchRefusesEmptyToken(t *testing.T) {
	a := require.New(t)
	broker := newFakeBroker(t, true)
	client, err := NewBrokerClient()
	a.NoError(err)

	_, _, err = client.WaitMatch(context.Background(), broker.addr(), nil)
	a.ErrorIs(err, errNoMatchToken)
}

func TestP2PDialFailsWithoutMatch(t *testing.T) {
	tests := []struct {
		name  string
		token string
		code  string
	}{
		{name: "empty", token: "", code: "invalid_p2p_token"},
		{name: "not hex", token: "zz", code: "invalid_p2p_token"},
		{
			name:  "15 bytes",
			token: strings.Repeat("ab", 15),
			code:  "invalid_p2p_token",
		},
		{
			name:  "33 bytes",
			token: strings.Repeat("ab", 33),
			code:  "invalid_p2p_token",
		},
		{
			name:  "random token, no peer",
			token: strings.Repeat("ab", 16),
			code:  "p2p_match_failed",
		},
		{
			name:  "static token, no peer",
			token: strings.Repeat("ab", 32),
			code:  "p2p_match_failed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			d, rec := newTestDaemon(t, VerificationModeQuick, false)
			d.matchTimeout = 200 * time.Millisecond
			broker := newFakeBroker(t, false)

			d.handleDial(Command{
				ID: "dial",
				Params: mustJSON(DialParams{
					Transport:  "p2p",
					BrokerAddr: broker.addr(),
					P2PToken:   tt.token,
				}),
			})

			evt := rec.waitFor(t, func(e recordedEvent) bool {
				return e.ID == "dial"
			})
			a.Equal(EvtError, evt.Evt)
			a.Equal(tt.code, evt.Data["code"], evt.Data["error"])

			// The failed dial no longer holds the storage.
			deadline := time.Now().Add(testEventTimeout)
			for d.storageBusy() {
				a.True(time.Now().Before(deadline), "dial never ended")
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}

// p2pTokenFor returns the static p2p token that d derives for the peer
// with the PKIX public key peer.
func p2pTokenFor(t *testing.T, d *Daemon, peer []byte) []byte {
	a := require.New(t)
	token, err := d.deriveP2PToken(fingerprint.Base64(peer))
	a.NoError(err)
	return token
}

// A p2p server stops registering the tokens that remove_p2p_token
// removes: its own token and those that generate_p2p_token added.
func TestRemovedP2PTokensAreNotRegistered(t *testing.T) {
	a := require.New(t)
	d, rec := newTestDaemon(t, VerificationModeQuick, false)
	broker := newFakeBroker(t, false)
	peerA := newTestPeerKey(t)
	peerB := newTestPeerKey(t)
	peerC := newTestPeerKey(t)
	tokenA := p2pTokenFor(t, d, peerA)
	tokenB := p2pTokenFor(t, d, peerB)
	tokenC := p2pTokenFor(t, d, peerC)

	d.handleStartServer(Command{
		ID: "start",
		Params: mustJSON(StartServerParams{
			Addr: "127.0.0.1:0", Transport: "p2p",
			BrokerAddr: broker.addr(), PeerPubB64: fingerprint.Base64(peerA),
		}),
	})
	rec.waitFor(t, isEvent(EvtServerStarted))
	d.handleGenerateP2PToken(Command{
		ID: "gen",
		Params: mustJSON(MapS{
			"broker_addr":  broker.addr(),
			"peer_pub_b64": fingerprint.Base64(peerB),
		}),
	})
	evt := rec.waitFor(t, func(e recordedEvent) bool { return e.ID == "gen" })
	a.Equal(EvtResponse, evt.Evt, "generate failed: %v", evt.Data)

	for _, token := range [][]byte{tokenA, tokenB} {
		id := ID("rm-" + hex.EncodeToString(token[:4]))
		d.handleRemoveP2PToken(Command{
			ID:     id,
			Params: mustJSON(MapS{"token": hex.EncodeToString(token)}),
		})
		evt := rec.waitFor(t, func(e recordedEvent) bool { return e.ID == id })
		a.Equal(EvtResponse, evt.Evt, "remove failed: %v", evt.Data)
	}

	d.mu.RLock()
	l, ok := d.p2pListener.(*p2pListener)
	d.mu.RUnlock()
	a.True(ok)
	// The broker has the REGISTERs sent so far: the punch socket sent
	// tokenA's first.
	before := len(broker.waitRegistered(t, tokenB))
	a.NoError(l.refreshRegistration())
	// The broker reads the punch socket's packets in order, so once it
	// has the REGISTER of tokenC it has those of the refresh as well.
	a.NoError(l.RegisterToken(tokenC, nil))
	after := broker.waitRegistered(t, tokenC)[before:]
	a.Len(after, 1)
	a.True(relaybroker.TokenMatches(after[0], tokenC))
}

// Each token is registered under an X25519 key of its own, which its
// refreshes keep, so the broker cannot link one token to another.
func TestBrokerRegistrationsUseOwnKeys(t *testing.T) {
	a := require.New(t)
	d, rec := newTestDaemon(t, VerificationModeQuick, false)
	broker := newFakeBroker(t, false)
	peers := make([][]byte, 4)
	tokens := make([][]byte, len(peers))
	for i := range peers {
		peers[i] = newTestPeerKey(t)
		tokens[i] = p2pTokenFor(t, d, peers[i])
	}

	// The p2p server's own token, and those added to it.
	d.handleStartServer(Command{
		ID: "start",
		Params: mustJSON(StartServerParams{
			Addr: "127.0.0.1:0", Transport: "p2p", BrokerAddr: broker.addr(),
			PeerPubB64: fingerprint.Base64(peers[0]),
		}),
	})
	rec.waitFor(t, isEvent(EvtServerStarted))
	for _, peer := range peers[1:] {
		_, err := d.GenerateP2PToken(broker.addr(), fingerprint.Base64(peer))
		a.NoError(err)
	}
	d.mu.RLock()
	l, ok := d.p2pListener.(*p2pListener)
	d.mu.RUnlock()
	a.True(ok)
	a.NoError(l.refreshRegistration())

	// Each token has been registered twice; wait for the refreshes.
	var keys []string
	deadline := time.Now().Add(testEventTimeout)
	for _, token := range tokens {
		for {
			n := 0
			for _, r := range broker.registrations() {
				if relaybroker.TokenMatches(r, token) {
					n++
				}
			}
			if n >= 2 {
				break
			}
			a.True(time.Now().Before(deadline), "no refresh of %x", token)
			time.Sleep(10 * time.Millisecond)
		}
		got := broker.keysFor(token)
		a.Len(got, 1, "token %x changed keys", token)
		keys = append(keys, got[0])
	}

	// A dial that waits for a match registers its token under the
	// token's key, which a second dial of it gets back, and a dial of
	// another token under a key of its own.
	matcher := newFakeBroker(t, true)
	client, err := NewBrokerClient()
	a.NoError(err)
	for _, token := range [][]byte{tokens[0], tokens[0], tokens[1]} {
		conn, _, err := client.WaitMatch(t.Context(), matcher.addr(), token)
		a.NoError(err)
		a.NoError(conn.Close())
	}
	for _, token := range tokens[:2] {
		dialKeys := matcher.keysFor(token)
		a.Len(dialKeys, 1)
		keys = append(keys, dialKeys...)
	}

	slices.Sort(keys)
	a.Len(slices.Compact(keys), len(tokens)+2, "a key was reused")
}

// A dial retried after it found no match registers its token under the
// same broker key, so that the broker refreshes the first dial's
// registration instead of matching the retry with it.
func TestWaitMatchRetryKeepsBrokerKey(t *testing.T) {
	a := require.New(t)
	broker := newFakeBroker(t, false)
	client, err := NewBrokerClient()
	a.NoError(err)
	token := []byte(strings.Repeat("r", 32))

	for n := 1; n <= 2; n++ {
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() {
			_, _, err := client.WaitMatch(ctx, broker.addr(), token)
			done <- err
		}()
		deadline := time.Now().Add(testEventTimeout)
		for registrationsOf(broker, token) < n {
			a.True(time.Now().Before(deadline), "dial %d not registered", n)
			time.Sleep(10 * time.Millisecond)
		}
		cancel()
		a.ErrorIs(<-done, context.Canceled)
	}
	a.Len(broker.keysFor(token), 1)
}

// registrationsOf returns how many REGISTERs of token b has received.
func registrationsOf(b *fakeBroker, token []byte) int {
	n := 0
	for _, r := range b.registrations() {
		if relaybroker.TokenMatches(r, token) {
			n++
		}
	}
	return n
}

// A token keeps its broker identity at one broker while it is in use
// and for brokerIDHold after, and gets a new one once that has passed.
func TestBrokerIdentityHold(t *testing.T) {
	a := require.New(t)
	b, err := NewBrokerClient()
	a.NoError(err)
	const brokerAddr = "127.0.0.1:1"
	token := []byte(strings.Repeat("h", 32))

	first, err := b.identity(brokerAddr, token)
	a.NoError(err)
	b.release(brokerAddr, token)
	again, err := b.identity(brokerAddr, token)
	a.NoError(err)
	a.Same(first, again)
	other, err := b.identity("127.0.0.1:2", token)
	a.NoError(err)
	a.NotSame(first, other)

	b.release(brokerAddr, token)
	b.mu.Lock()
	b.ids[identityKey(brokerAddr, token)].until = time.Now().Add(-time.Second)
	b.mu.Unlock()
	fresh, err := b.identity(brokerAddr, token)
	a.NoError(err)
	a.NotSame(first, fresh)
}

// generate_p2p_token registers its token from the p2p server's punch
// socket, the address that the broker gives a peer who dials the token,
// and fails when no p2p server runs for the broker.
func TestGenerateP2PTokenRegistersFromPunchSocket(t *testing.T) {
	a := require.New(t)
	d, rec := newTestDaemon(t, VerificationModeQuick, false)
	broker := newFakeBroker(t, false)
	other := newFakeBroker(t, false)
	peerA := newTestPeerKey(t)
	peerB := newTestPeerKey(t)

	generate := func(id ID, brokerAddr string, peer []byte) recordedEvent {
		params := MapS{"broker_addr": brokerAddr}
		if peer != nil {
			params["peer_pub_b64"] = fingerprint.Base64(peer)
		}
		d.handleGenerateP2PToken(Command{ID: id, Params: mustJSON(params)})
		return rec.waitFor(t, func(e recordedEvent) bool { return e.ID == id })
	}

	evt := generate("no-server", broker.addr(), peerB)
	a.Equal(EvtError, evt.Evt)
	a.Equal("p2p_server_not_running", evt.Data["code"], evt.Data["error"])
	a.Empty(broker.registrations())
	a.Empty(d.GetP2PTokens())

	d.handleStartServer(Command{
		ID: "start",
		Params: mustJSON(StartServerParams{
			Addr: "127.0.0.1:0", Transport: "p2p",
			BrokerAddr: broker.addr(), PeerPubB64: fingerprint.Base64(peerA),
		}),
	})
	rec.waitFor(t, isEvent(EvtServerStarted))
	d.mu.RLock()
	l, ok := d.p2pListener.(*p2pListener)
	d.mu.RUnlock()
	a.True(ok)
	punch := l.Addr().String()

	evt = generate("other-broker", other.addr(), peerB)
	a.Equal(EvtError, evt.Evt)
	a.Equal("broker_addr_mismatch", evt.Data["code"], evt.Data["error"])
	a.Empty(other.registrations())

	tests := []struct {
		name string
		peer []byte
		mode string
	}{
		{name: "random", mode: "random"},
		{name: "static", peer: peerB, mode: "static"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			evt := generate(ID("gen-"+tt.name), broker.addr(), tt.peer)
			a.Equal(EvtResponse, evt.Evt, "generate failed: %v", evt.Data)
			tokenHex, _ := evt.Data["token"].(string)
			token, err := hex.DecodeString(tokenHex)
			a.NoError(err)
			broker.waitRegistered(t, token)
			a.Equal([]string{punch}, broker.sourcesFor(token))
			idx := slices.IndexFunc(d.GetP2PTokens(), func(pt p2pToken) bool {
				return pt.Token == tokenHex
			})
			a.NotEqual(-1, idx)
			a.Equal(tt.mode, d.GetP2PTokens()[idx].Mode)
		})
	}
}

// HolePunch sends its whole burst of NAT kicks to the peer before it
// returns. It used to send the burst from a goroutine that it cancelled
// on return, so the peer got none or one.
func TestHolePunchSendsKickBurst(t *testing.T) {
	a := require.New(t)
	loopback := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	peer, err := net.ListenUDP("udp4", loopback)
	a.NoError(err)
	defer peer.Close()
	punch, err := net.ListenUDP("udp4", loopback)
	a.NoError(err)
	client, err := NewBrokerClient()
	a.NoError(err)

	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	sess, err := client.HolePunch(
		t.Context(), punch, peerAddr.IP, uint16(peerAddr.Port),
		DefaultHolePunchTimeout,
	)
	a.NoError(err)
	defer sess.Close()

	// The kicks were sent before HolePunch returned; wait only for the
	// loopback to deliver them.
	a.NoError(peer.SetReadDeadline(time.Now().Add(testEventTimeout)))
	buf := make([]byte, 1500)
	kicks := 0
	for kicks < natKicks {
		n, src, err := peer.ReadFromUDP(buf)
		a.NoError(err, "got %d of %d kicks", kicks, natKicks)
		if n == 1 && buf[0] == 0 &&
			src.Port == punch.LocalAddr().(*net.UDPAddr).Port {
			kicks++
		}
	}
}

// HolePunch fails with ErrHolePunchFailed when it can send no kick.
func TestHolePunchFailsWithoutKick(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*net.UDPConn) context.Context
	}{
		{
			name: "context done",
			setup: func(*net.UDPConn) context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
		},
		{
			name: "socket closed",
			setup: func(conn *net.UDPConn) context.Context {
				_ = conn.Close()
				return context.Background()
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			punch, err := net.ListenUDP(
				"udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
			)
			a.NoError(err)
			defer punch.Close()
			client, err := NewBrokerClient()
			a.NoError(err)

			ctx := tt.setup(punch)
			_, err = client.HolePunch(
				ctx, punch, net.IPv4(127, 0, 0, 1), 9, time.Second,
			)
			a.ErrorIs(err, ErrHolePunchFailed)
		})
	}
}

// A p2p server's refreshes keep its tokens' expiry a refresh interval
// ahead, so that a listed token does not expire while the server
// refreshes it. Neither a refresh nor a new token needs a STUN_ECHO.
func TestP2PRefreshExtendsTokenExpiry(t *testing.T) {
	a := require.New(t)
	d, rec := newTestDaemon(t, VerificationModeQuick, false)
	broker := newFakeBroker(t, false)
	peer := newTestPeerKey(t)
	d.handleStartServer(Command{
		ID: "start",
		Params: mustJSON(StartServerParams{
			Addr: "127.0.0.1:0", Transport: "p2p",
			BrokerAddr: broker.addr(), PeerPubB64: fingerprint.Base64(peer),
		}),
	})
	rec.waitFor(t, isEvent(EvtServerStarted))
	d.mu.RLock()
	l, ok := d.p2pListener.(*p2pListener)
	d.mu.RUnlock()
	a.True(ok)

	broker.noEcho.Store(true)
	random, err := d.GenerateP2PToken(broker.addr(), "")
	a.NoError(err)
	tokens := d.GetP2PTokens()
	a.Len(tokens, 2)

	refreshed := time.Now()
	a.NoError(l.refreshRegistration())
	for _, pt := range d.GetP2PTokens() {
		a.Equal(p2pTokenTTL, pt.TTL)
		a.False(pt.ExpiresAt.Before(refreshed.Add(p2pTokenTTL)),
			"token %s expires at %v", pt.Token, pt.ExpiresAt)
		token, err := hex.DecodeString(pt.Token)
		a.NoError(err)
		deadline := time.Now().Add(testEventTimeout)
		for registrationsOf(broker, token) < 2 {
			a.True(time.Now().Before(deadline), "%s not refreshed", pt.Token)
			time.Sleep(10 * time.Millisecond)
		}
	}
	a.Contains([]string{tokens[0].Token, tokens[1].Token}, random)
}
