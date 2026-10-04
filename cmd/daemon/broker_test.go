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

	mu         sync.Mutex
	registered [][]byte
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
			_, _ = b.conn.WriteToUDP(relaybroker.BuildEchoResponse(src), src)
			continue
		}
		token, peerEphPub, _, _, err := relaybroker.ParseRegister(pkt)
		if err != nil {
			continue
		}
		b.mu.Lock()
		b.registered = append(b.registered, slices.Clone(token))
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
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	peerPub, err := ecdh.X25519().NewPublicKey(peerEphPub)
	if err != nil {
		panic(err)
	}
	shared, err := eph.ECDH(peerPub)
	if err != nil {
		panic(err)
	}
	key := sha256.Sum256(shared)
	brokerEphPub := eph.PublicKey().Bytes()
	plaintext := relaybroker.PeerMatchedPlaintext(
		token, make([]byte, 32), b.peer.IP, uint16(b.peer.Port),
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
	a.NoError(l.RegisterToken(tokenC))
	after := broker.waitRegistered(t, tokenC)[before:]
	a.Len(after, 1)
	a.True(relaybroker.TokenMatches(after[0], tokenC))
}
