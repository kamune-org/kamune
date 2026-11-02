package udppath

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
)

func testAEAD(t testing.TB) pathKeys {
	t.Helper()
	c2s, err := chacha20poly1305.New(bytes.Repeat([]byte{1}, keyLen))
	require.New(t).NoError(err)
	s2c, err := chacha20poly1305.New(bytes.Repeat([]byte{2}, keyLen))
	require.New(t).NoError(err)
	return pathKeys{c2s: c2s, s2c: s2c}
}

func TestSealOpen(t *testing.T) {
	keys := testAEAD(t)
	tests := []struct {
		name    string
		payload []byte
		typ     byte
		size    int
	}{
		{"data one byte", []byte{7}, typeData, DataOverhead + 1},
		{"data full", bytes.Repeat([]byte{7}, KCPMTU), typeData, MaxDatagram},
		{"close", nil, typeClose, CloseSize},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			pkt := sealPacket(nil, keys.c2s, tc.typ, 9, 3, tc.payload)
			a.Len(pkt, tc.size)
			a.True(validPacket(pkt))
			m, err := parseSealed(pkt)
			a.NoError(err)
			a.Equal(sealedMsg{typ: tc.typ, rid: 9, ctr: 3}, m)
			plain, err := openPacket(nil, keys.c2s, m.ctr, pkt)
			a.NoError(err)
			a.Equal(len(tc.payload), len(plain))
			a.True(bytes.Equal(tc.payload, plain))

			_, err = openPacket(nil, keys.s2c, m.ctr, pkt)
			a.Error(err, "the other direction's key opens nothing")
			_, err = openPacket(nil, keys.c2s, m.ctr+1, pkt)
			a.Error(err, "the counter is the nonce")
		})
	}
}

func TestSealedHeaderIsAuthenticated(t *testing.T) {
	a := require.New(t)
	keys := testAEAD(t)
	pkt := sealPacket(nil, keys.c2s, typeData, 9, 3, []byte("kcp"))
	for _, off := range []int{0, 4, 15} {
		bad := bytes.Clone(pkt)
		bad[off] ^= 1
		_, err := openPacket(nil, keys.c2s, 3, bad)
		a.Error(err, "byte %d", off)
	}
}

func TestParseSealedMalformed(t *testing.T) {
	keys := testAEAD(t)
	data := func(n int) []byte {
		return sealPacket(nil, keys.c2s, typeData, 9, 3, make([]byte, n))
	}
	closePkt := func() []byte {
		return sealPacket(nil, keys.c2s, typeClose, 9, 3, nil)
	}
	withCtr := func(c uint64) []byte {
		b := data(1)
		binary.BigEndian.PutUint64(b[sealedCtr:], c)
		return b
	}
	tests := []struct {
		pkt  func() []byte
		name string
	}{
		{name: "data 32 bytes", pkt: func() []byte { return data(1)[:32] }},
		{name: "data 1233 bytes", pkt: func() []byte {
			return append(data(KCPMTU), 0)
		}},
		{name: "counter zero", pkt: func() []byte { return withCtr(0) }},
		{name: "counter 2^63", pkt: func() []byte { return withCtr(maxCounter) }},
		{name: "zero rid", pkt: func() []byte {
			return sealPacket(nil, keys.c2s, typeData, 0, 3, []byte{1})
		}},
		{name: "close 31 bytes", pkt: func() []byte { return closePkt()[:31] }},
		{name: "close 33 bytes", pkt: func() []byte {
			return append(closePkt(), 0)
		}},
		{name: "version 2", pkt: func() []byte {
			b := data(1)
			b[1] = 2
			return b
		}},
		{name: "reserved", pkt: func() []byte {
			b := closePkt()
			b[2] = 1
			return b
		}},
		{name: "hello type", pkt: func() []byte { return encodeHello(9, nil) }},
		{name: "empty", pkt: func() []byte { return nil }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			_, err := parseSealed(tc.pkt())
			a.ErrorIs(err, errMalformed)
		})
	}
}

func TestValidPacketAndClassify(t *testing.T) {
	var cookie [cookieLen]byte
	eph := bytes.Repeat([]byte{0x42}, ephLen)
	tests := []struct {
		name  string
		pkt   []byte
		class class
		valid bool
	}{
		{"hello", encodeHello(1, nil), classOurs, true},
		{"cookie", encodeCookie(1, cookie), classOurs, true},
		{"init", encodeInit(1, cookie, eph, nil), classOurs, true},
		{"accept", encodeAcceptBody(1, 2, eph), classOurs, true},
		{"accept zero sid", encodeAcceptBody(1, 0, eph), classOurs, false},
		{"type 0x07", append([]byte{0x07, Version, 0, 0}, 0, 0, 0, 1),
			classOurs, false},
		{"type 0x0f", []byte{0x0F, Version, 0, 0, 0, 0, 0, 1}, classOurs, false},
		{"kick", []byte{0x00}, classKick, false},
		{"empty", nil, classKick, false},
		{"broker", []byte("KBRK0000"), classForeign, false},
		{"oversize data", append([]byte{typeData, Version, 0, 0, 0, 0, 0, 1},
			make([]byte, 1493)...), classOurs, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			a.Equal(tc.class, classify(tc.pkt))
			a.Equal(tc.valid, validPacket(tc.pkt))
		})
	}
}

func BenchmarkSealOpen1200(b *testing.B) {
	keys := testAEAD(b)
	payload := bytes.Repeat([]byte{7}, KCPMTU)
	var sealBuf [MaxDatagram]byte
	var openBuf [KCPMTU]byte
	b.SetBytes(KCPMTU)
	b.ReportAllocs()
	var ctr uint64
	for b.Loop() {
		ctr++
		pkt := sealPacket(sealBuf[:0], keys.c2s, typeData, 9, ctr, payload)
		if _, err := openPacket(openBuf[:], keys.c2s, ctr, pkt); err != nil {
			b.Fatal(err)
		}
	}
}
