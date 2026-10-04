package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"net"
	"strings"
	"testing"
	"time"

	relaybroker "github.com/kamune-org/kamune/pkg/relayconn/broker"
	"github.com/stretchr/testify/require"
)

// fakeBroker answers STUN_ECHO requests. When match is set, it answers
// each REGISTER with a PEER_MATCHED for the registered token, as the
// broker does once the other peer has registered it; otherwise it
// ignores REGISTERs, as when no peer holds the token.
type fakeBroker struct {
	conn  *net.UDPConn
	match bool
	peer  *net.UDPAddr
}

func newFakeBroker(t *testing.T, match bool) *fakeBroker {
	a := require.New(t)
	conn, err := net.ListenUDP(
		"udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
	)
	a.NoError(err)
	b := &fakeBroker{
		conn:  conn,
		match: match,
		peer:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9},
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
		if err != nil || !b.match {
			continue
		}
		_, _ = b.conn.WriteToUDP(b.peerMatched(token, peerEphPub), src)
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
