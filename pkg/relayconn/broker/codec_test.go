package broker

import (
	"bytes"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBrokerOpenNotify_TamperedCiphertext(t *testing.T) {
	a := require.New(t)

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	brokerEphPub := make([]byte, 32)
	for i := range brokerEphPub {
		brokerEphPub[i] = byte(i + 32)
	}

	plaintext := TokenAssignedPlaintext(make([]byte, 16), 60)
	nonce, sealed := SealNotify(key, brokerEphPub, plaintext)

	sealed[len(sealed)-1] ^= 0xFF

	_, err := OpenNotify(key, brokerEphPub, nonce, sealed)
	a.Error(err, "tampered ciphertext must be rejected")
}

// TestTokenMatches checks NOTIFY token matching against the token a
// peer registered with, including a 32-byte static token that travels
// truncated to 16 bytes.
func TestTokenMatches(t *testing.T) {
	static := make([]byte, 32)
	for i := range static {
		static[i] = byte(i + 1)
	}
	other := bytes.Repeat([]byte{0xee}, 32)
	short := []byte("short")

	// notifyToken runs token through the broker wire format: REGISTER
	// as the peer sends it, then PEER_MATCHED as the broker echoes it.
	notifyToken := func(token []byte) []byte {
		pkt := BuildRegister(token, make([]byte, 32), net.IPv4zero, 1)
		wire, _, _, _, err := ParseRegister(pkt)
		require.New(t).NoError(err)
		plain := PeerMatchedPlaintext(wire, make([]byte, 32), nil, 1)
		p, err := ParseNotifyPayload(plain)
		require.New(t).NoError(err)
		return p.Token
	}

	tests := []struct {
		name     string
		notified []byte
		token    []byte
		want     bool
	}{
		{"static 32-byte token", notifyToken(static), static, true},
		{"16-byte token", notifyToken(static[:16]), static[:16], true},
		{"short token", notifyToken(short), short, true},
		{"different token", notifyToken(other), static, false},
		{"empty token", notifyToken(static), nil, false},
		{"notified not wire size", static, static, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			a.Equal(tc.want, TokenMatches(tc.notified, tc.token))
		})
	}
}

func TestWireToken(t *testing.T) {
	a := require.New(t)
	static := bytes.Repeat([]byte{0x42}, 32)
	a.Nil(WireToken(nil))
	a.Equal(static[:TokenSize], WireToken(static))
	a.Equal(
		append([]byte("ab"), make([]byte, TokenSize-2)...),
		WireToken([]byte("ab")),
	)
}
