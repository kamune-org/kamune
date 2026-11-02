package udppath

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWireRoundTrip(t *testing.T) {
	a := require.New(t)
	var cookie [cookieLen]byte
	for i := range cookie {
		cookie[i] = byte(i + 1)
	}
	eph := bytes.Repeat([]byte{0x42}, ephLen)

	h, err := parseHello(encodeHello(7, nil))
	a.NoError(err)
	a.Equal(uint32(7), h.cid)
	a.Equal([macLen]byte{}, h.mac1)

	c, err := parseCookie(encodeCookie(8, cookie))
	a.NoError(err)
	a.Equal(uint32(8), c.cid)
	a.Equal(cookie, c.cookie)

	in, err := parseInit(encodeInit(9, cookie, eph, nil))
	a.NoError(err)
	a.Equal(uint32(9), in.cid)
	a.Equal(cookie, in.cookie)
	a.Equal(eph, in.cEph[:])
	a.Equal([macLen]byte{}, in.mac1)

	ac, err := parseAccept(encodeAcceptBody(10, 11, eph))
	a.NoError(err)
	a.Equal(uint32(10), ac.cid)
	a.Equal(uint32(11), ac.sid)
	a.Equal(eph, ac.sEph[:])
}

func TestWireMalformed(t *testing.T) {
	var cookie [cookieLen]byte
	eph := bytes.Repeat([]byte{0x42}, ephLen)
	hello := func() []byte { return encodeHello(7, nil) }
	init := func() []byte { return encodeInit(9, cookie, eph, nil) }
	accept := func() []byte { return encodeAcceptBody(10, 11, eph) }
	cookieP := func() []byte { return encodeCookie(8, cookie) }
	parse := map[string]func([]byte) error{
		"hello":  func(b []byte) error { _, err := parseHello(b); return err },
		"cookie": func(b []byte) error { _, err := parseCookie(b); return err },
		"init":   func(b []byte) error { _, err := parseInit(b); return err },
		"accept": func(b []byte) error { _, err := parseAccept(b); return err },
	}
	tests := []struct {
		name   string
		parser string
		pkt    func() []byte
	}{
		{"hello 1199 bytes", "hello", func() []byte { return hello()[:1199] }},
		{"hello 1201 bytes", "hello", func() []byte {
			return append(hello(), 0)
		}},
		{"hello padding", "hello", func() []byte {
			b := hello()
			b[HelloSize-1] = 1
			return b
		}},
		{"hello version 2", "hello", func() []byte {
			b := hello()
			b[1] = 2
			return b
		}},
		{"hello reserved", "hello", func() []byte {
			b := hello()
			b[3] = 1
			return b
		}},
		{"type 0x07", "hello", func() []byte {
			b := hello()
			b[0] = 0x07
			return b
		}},
		{"hello zero cid", "hello", func() []byte { return encodeHello(0, nil) }},
		{"cookie zero cid", "cookie", func() []byte {
			return encodeCookie(0, cookie)
		}},
		{"cookie 29 bytes", "cookie", func() []byte {
			return append(cookieP(), 0)
		}},
		{"init padding", "init", func() []byte {
			b := init()
			b[initPad] = 1
			return b
		}},
		{"init 1199 bytes", "init", func() []byte { return init()[:1199] }},
		{"init as hello", "hello", init},
		{"init zero cid", "init", func() []byte {
			return encodeInit(0, cookie, eph, nil)
		}},
		{"accept zero sid", "accept", func() []byte {
			return encodeAcceptBody(10, 0, eph)
		}},
		{"accept zero cid", "accept", func() []byte {
			return encodeAcceptBody(0, 11, eph)
		}},
		{"accept 61 bytes", "accept", func() []byte {
			return append(accept(), 0)
		}},
		{"empty", "accept", func() []byte { return nil }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			a.ErrorIs(parse[tc.parser](tc.pkt()), errMalformed)
		})
	}
}

func TestKnockMAC(t *testing.T) {
	key := bytes.Repeat([]byte{1}, knockKeyLen)
	other := bytes.Repeat([]byte{2}, knockKeyLen)
	var cookie [cookieLen]byte
	eph := bytes.Repeat([]byte{0x42}, ephLen)
	tests := []struct {
		name    string
		send    []byte
		check   []byte
		allowed bool
	}{
		{"right key", key, key, true},
		{"wrong key", other, key, false},
		{"no key sent", nil, key, false},
		{"receiver without key", key, nil, true},
		{"neither has a key", nil, nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			hb := encodeHello(7, tc.send)
			h, err := parseHello(hb)
			a.NoError(err)
			a.Equal(tc.allowed, checkKnock(tc.check, h.mac1, hb[:helloMAC1]))

			ib := encodeInit(7, cookie, eph, tc.send)
			in, err := parseInit(ib)
			a.NoError(err)
			a.Equal(tc.allowed, checkKnock(tc.check, in.mac1, ib[:initMAC1]))

			if tc.send == nil {
				a.Equal([macLen]byte{}, h.mac1)
				a.Equal([macLen]byte{}, in.mac1)
			}
		})
	}
}
