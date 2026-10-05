package main

import (
	"bytes"
	"encoding/binary"
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

// matchBroker matches two REGISTERs of one token under different keys,
// as the relay's broker does: it sends each side a PEER_MATCHED that
// names the other's source address.
type matchBroker struct {
	conn *net.UDPConn
	mu   sync.Mutex
	held map[string]matchReg
}

// matchReg is a registration that matchBroker holds.
type matchReg struct {
	addr *net.UDPAddr
	key  []byte
}

func newMatchBroker(t *testing.T) *matchBroker {
	a := require.New(t)
	conn, err := net.ListenUDP(
		"udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
	)
	a.NoError(err)
	t.Cleanup(func() { _ = conn.Close() })
	b := &matchBroker{conn: conn, held: make(map[string]matchReg)}
	go b.serve()
	return b
}

func (b *matchBroker) addr() string { return b.conn.LocalAddr().String() }

// heldKeys returns the keys of the registrations that the broker holds.
func (b *matchBroker) heldKeys() [][]byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	var keys [][]byte
	for _, r := range b.held {
		keys = append(keys, r.key)
	}
	return keys
}

func (b *matchBroker) serve() {
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
		token, key, _, _, err := relaybroker.ParseRegister(pkt)
		if err != nil {
			continue
		}
		k := hex.EncodeToString(token)
		b.mu.Lock()
		held, ok := b.held[k]
		if !ok || bytes.Equal(held.key, key) {
			b.held[k] = matchReg{addr: src, key: slices.Clone(key)}
			b.mu.Unlock()
			continue
		}
		delete(b.held, k)
		b.mu.Unlock()
		_, _ = b.conn.WriteToUDP(
			sealPeerMatched(token, held.key, src, key), held.addr,
		)
		_, _ = b.conn.WriteToUDP(
			sealPeerMatched(token, key, held.addr, held.key), src,
		)
	}
}

// A p2p dial reaches a p2p server through the broker.
func TestP2PDialReachesServer(t *testing.T) {
	a := require.New(t)
	broker := newMatchBroker(t)
	server, srec := newTestDaemon(t, VerificationModeQuick, false)
	client, crec := newTestDaemon(t, VerificationModeQuick, false)
	t.Cleanup(server.stopServer)
	t.Cleanup(client.stopServer)
	trustPeer(t, server, client)
	trustPeer(t, client, server)
	clientKey, err := client.store().PublicKey()
	a.NoError(err)

	server.handleStartServer(Command{
		ID: "start",
		Params: mustJSON(StartServerParams{
			Addr: "127.0.0.1:0", Transport: "p2p", BrokerAddr: broker.addr(),
			PeerPubB64: fingerprint.Base64(clientKey),
		}),
	})
	evt := srec.waitFor(t, func(e recordedEvent) bool { return e.ID == "start" })
	a.Equal(EvtServerStarted, evt.Evt, "start failed: %v", evt.Data)
	tokens := server.GetP2PTokens()
	a.Len(tokens, 1)

	client.handleDial(Command{
		ID: "dial",
		Params: mustJSON(DialParams{
			Transport: "p2p", BrokerAddr: broker.addr(),
			P2PToken: tokens[0].Token,
		}),
	})
	evt = crec.waitFor(t, func(e recordedEvent) bool {
		return e.ID == "dial" &&
			(e.Evt == EvtSessionStarted || e.Evt == EvtError)
	})
	a.Equal(EvtSessionStarted, evt.Evt, "dial failed: %v", evt.Data)
	srec.waitFor(t, isEvent(EvtSessionStarted))
}

// A p2p listener keeps the broker's packets away from KCP, which would
// take a NOTIFY for a new session, and lets in packets only from hosts
// that a PEER_MATCHED for one of its tokens named. On such a match it
// punches toward the dialer.
func TestP2PListenerHandlesPeerMatched(t *testing.T) {
	a := require.New(t)
	stranger, err := net.ListenUDP(
		"udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2)},
	)
	if err != nil {
		t.Skipf("no second loopback address: %v", err)
	}
	defer stranger.Close()
	dialer, err := net.ListenUDP(
		"udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
	)
	a.NoError(err)
	defer dialer.Close()

	broker := newFakeBroker(t, false)
	client, err := NewBrokerClient()
	a.NoError(err)
	token := []byte(strings.Repeat("m", 32))
	l, err := newP2PListener(
		client, broker.addr(), token, nil, "127.0.0.1:0", nil,
	)
	a.NoError(err)
	defer l.Close()
	broker.waitRegistered(t, token)
	keys := broker.keysFor(token)
	a.Len(keys, 1)
	key, err := hex.DecodeString(keys[0])
	a.NoError(err)

	accepted := make(chan net.Addr, 4)
	go func() {
		for {
			sess, err := l.kcp.AcceptKCP()
			if err != nil {
				return
			}
			accepted <- sess.RemoteAddr()
		}
	}()

	// Any packet of 24 bytes or more from a new address starts a KCP
	// session.
	kcpPkt := make([]byte, 32)
	binary.LittleEndian.PutUint32(kcpPkt, 1)
	send := func(from *net.UDPConn, pkt []byte) {
		_, err := from.WriteToUDP(pkt, l.Addr())
		a.NoError(err)
	}

	// A match for another token, naming the stranger, does not let the
	// stranger in.
	broker.peer = stranger.LocalAddr().(*net.UDPAddr)
	other := relaybroker.WireToken([]byte(strings.Repeat("o", 32)))
	send(broker.conn, broker.peerMatched(other, key))
	send(stranger, kcpPkt)

	broker.peer = dialer.LocalAddr().(*net.UDPAddr)
	send(broker.conn, broker.peerMatched(relaybroker.WireToken(token), key))

	a.NoError(dialer.SetReadDeadline(time.Now().Add(testEventTimeout)))
	buf := make([]byte, 1500)
	n, src, err := dialer.ReadFromUDP(buf)
	a.NoError(err, "the listener did not punch toward the dialer")
	a.Equal([]byte{0}, buf[:n])
	a.Equal(l.Addr().String(), src.String())

	// The packets above reached the punch socket before this one, so a
	// session for any of them would be accepted first.
	send(dialer, kcpPkt)
	select {
	case addr := <-accepted:
		a.Equal(dialer.LocalAddr().String(), addr.String())
	case <-time.After(testEventTimeout):
		t.Fatal("the dialer's packet was not let in")
	}
}

// A p2p listener stops letting in a peer that the broker matched on a
// token once the token is removed: the peer still knows the listener's
// address, but cannot open a session without a new match.
func TestP2PListenerForgetsPeersOfRemovedTokens(t *testing.T) {
	a := require.New(t)
	other, err := net.ListenUDP(
		"udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2)},
	)
	if err != nil {
		t.Skipf("no second loopback address: %v", err)
	}
	defer other.Close()
	removed, err := net.ListenUDP(
		"udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
	)
	a.NoError(err)
	defer removed.Close()

	broker := newFakeBroker(t, false)
	client, err := NewBrokerClient()
	a.NoError(err)
	own := []byte(strings.Repeat("m", 32))
	extra := []byte(strings.Repeat("n", 32))
	l, err := newP2PListener(
		client, broker.addr(), own, nil, "127.0.0.1:0", nil,
	)
	a.NoError(err)
	defer l.Close()
	a.NoError(l.RegisterToken(extra, nil))
	broker.waitRegistered(t, extra)
	keyOf := func(token []byte) []byte {
		keys := broker.keysFor(token)
		a.Len(keys, 1)
		key, err := hex.DecodeString(keys[0])
		a.NoError(err)
		return key
	}

	accepted := make(chan net.Addr, 4)
	go func() {
		for {
			sess, err := l.kcp.AcceptKCP()
			if err != nil {
				return
			}
			accepted <- sess.RemoteAddr()
		}
	}()
	// match has the broker match token with peer, and waits for the
	// listener's kick toward peer, which it sends once it let peer in.
	match := func(token []byte, peer *net.UDPConn) {
		t.Helper()
		broker.peer = peer.LocalAddr().(*net.UDPAddr)
		_, err := broker.conn.WriteToUDP(
			broker.peerMatched(relaybroker.WireToken(token), keyOf(token)),
			l.Addr(),
		)
		a.NoError(err)
		a.NoError(peer.SetReadDeadline(time.Now().Add(testEventTimeout)))
		buf := make([]byte, 1500)
		n, _, err := peer.ReadFromUDP(buf)
		a.NoError(err, "the listener did not punch toward the peer")
		a.Equal([]byte{0}, buf[:n])
	}
	kcpPkt := make([]byte, 32)
	binary.LittleEndian.PutUint32(kcpPkt, 1)

	match(extra, removed)
	l.UnregisterToken(extra)
	match(own, other)

	// The removed token's peer sends first, so a session for it would
	// be accepted first.
	_, err = removed.WriteToUDP(kcpPkt, l.Addr())
	a.NoError(err)
	_, err = other.WriteToUDP(kcpPkt, l.Addr())
	a.NoError(err)
	select {
	case addr := <-accepted:
		a.Equal(other.LocalAddr().String(), addr.String(),
			"let in the peer of a removed token")
	case <-time.After(testEventTimeout):
		t.Fatal("the matched peer's packet was not let in")
	}
}

// startP2PServerFor starts a p2p server on d at broker with the static
// token for peer, and returns its listener.
func startP2PServerFor(
	t *testing.T, d *Daemon, rec *eventRecorder, broker string, peer []byte,
) *p2pListener {
	a := require.New(t)
	d.handleStartServer(Command{
		ID: "start",
		Params: mustJSON(StartServerParams{
			Addr: "127.0.0.1:0", Transport: "p2p", BrokerAddr: broker,
			PeerPubB64: fingerprint.Base64(peer),
		}),
	})
	evt := rec.waitFor(t, func(e recordedEvent) bool { return e.ID == "start" })
	a.Equal(EvtServerStarted, evt.Evt, "start failed: %v", evt.Data)
	d.mu.RLock()
	l, ok := d.p2pListener.(*p2pListener)
	d.mu.RUnlock()
	a.True(ok)
	return l
}

// When two peers run a p2p server for each other, both servers register
// the same static token, and the broker matches them with each other. A
// dial on the token from either side runs from its own server's punch
// socket, on the server's match, instead of waiting for a match of its
// own that the broker gives only after the other server's next refresh.
func TestP2PDialWhenBothServeTheToken(t *testing.T) {
	tests := []struct {
		name  string
		stale bool
	}{
		{name: "fresh match"},
		{name: "stale match", stale: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			broker := newMatchBroker(t)
			server, srec := newTestDaemon(t, VerificationModeQuick, false)
			client, crec := newTestDaemon(t, VerificationModeQuick, false)
			trustPeer(t, server, client)
			trustPeer(t, client, server)
			serverKey, err := server.store().PublicKey()
			a.NoError(err)
			clientKey, err := client.store().PublicKey()
			a.NoError(err)

			sl := startP2PServerFor(t, server, srec, broker.addr(), clientKey)
			cl := startP2PServerFor(t, client, crec, broker.addr(), serverKey)
			token := sl.token
			a.Equal(token, cl.token)
			key := wireKey(token)
			a.Eventually(func() bool {
				cl.matchMu.Lock()
				defer cl.matchMu.Unlock()
				_, ok := cl.matches[key]
				return ok
			}, testEventTimeout, 10*time.Millisecond)
			if tt.stale {
				cl.matchMu.Lock()
				m := cl.matches[key]
				m.at = time.Now().Add(-matchWindow)
				cl.matches[key] = m
				cl.matchMu.Unlock()
			}

			// Without the server's match, the dial would wait for a
			// refresh of the other server, 30 seconds away.
			client.matchTimeout = testEventTimeout / 3
			client.handleDial(Command{
				ID: "dial",
				Params: mustJSON(DialParams{
					Transport: "p2p", BrokerAddr: broker.addr(),
					P2PToken:   hex.EncodeToString(token),
					PeerPubB64: fingerprint.Base64(serverKey),
				}),
			})
			if tt.stale {
				// The dial sent a REGISTER, which the broker holds; the
				// other server's refresh matches it.
				a.Eventually(func() bool {
					return len(broker.heldKeys()) == 1
				}, testEventTimeout, 10*time.Millisecond)
				a.NoError(sl.refreshRegistration())
			}
			evt := crec.waitFor(t, func(e recordedEvent) bool {
				return e.ID == "dial" &&
					(e.Evt == EvtSessionStarted || e.Evt == EvtError)
			})
			a.Equal(EvtSessionStarted, evt.Evt, "dial failed: %v", evt.Data)
			srec.waitFor(t, isEvent(EvtSessionStarted))
		})
	}
}
