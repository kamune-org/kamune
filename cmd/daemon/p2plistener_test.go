package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/netip"
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

// A host that a PEER_MATCHED named is let in for matchedPeerIdle after
// the match and after each packet from it.
func TestP2PListenerPeerExpires(t *testing.T) {
	a := require.New(t)
	l := &p2pListener{peers: make(map[netip.Addr]time.Time)}
	ip := netip.MustParseAddr("192.0.2.1")
	src := net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, 4000))
	other := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 4000}

	a.False(l.admitted(src))
	l.admitPeer(ip)
	a.True(l.admitted(src))
	a.True(l.admitted(&net.UDPAddr{IP: src.IP, Port: 5000}))
	a.False(l.admitted(other))

	l.peers[ip] = time.Now().Add(-time.Second)
	a.False(l.admitted(src))
	// Admitting another host drops the expired one.
	l.admitPeer(other.AddrPort().Addr())
	a.NotContains(l.peers, ip)
	a.Len(l.peers, 1)
}
