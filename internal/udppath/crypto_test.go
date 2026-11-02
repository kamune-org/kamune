package udppath

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha512"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCookie(t *testing.T) {
	secret := bytes.Repeat([]byte{7}, 32)
	src := netip.MustParseAddrPort("192.0.2.10:4000")
	issued := time.Unix(1_800_000_000, 0)
	cookie := makeCookie(secret, issued, 99, src)
	flipped := cookie
	flipped[cookieLen-1] ^= 1
	tests := []struct {
		name   string
		cookie [cookieLen]byte
		secret []byte
		src    netip.AddrPort
		now    time.Time
		cid    uint32
		valid  bool
	}{
		{name: "at issue", now: issued, valid: true},
		{name: "ten seconds later", now: issued.Add(10 * time.Second),
			valid: true},
		{name: "twelve seconds later", now: issued.Add(12 * time.Second)},
		{name: "one second early", now: issued.Add(-time.Second), valid: true},
		{name: "two seconds early", now: issued.Add(-2 * time.Second)},
		{name: "other ip", now: issued,
			src: netip.MustParseAddrPort("192.0.2.11:4000")},
		{name: "other port", now: issued,
			src: netip.MustParseAddrPort("192.0.2.10:4001")},
		{name: "other cid", now: issued, cid: 98},
		{name: "mac bit flipped", now: issued, cookie: flipped},
		{name: "ipv4-mapped source", now: issued, valid: true,
			src: netip.MustParseAddrPort("[::ffff:192.0.2.10]:4000")},
		{name: "new secret", now: issued,
			secret: bytes.Repeat([]byte{8}, 32)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			if tc.cookie == ([cookieLen]byte{}) {
				tc.cookie = cookie
			}
			if tc.secret == nil {
				tc.secret = secret
			}
			if !tc.src.IsValid() {
				tc.src = src
			}
			if tc.cid == 0 {
				tc.cid = 99
			}
			a.Equal(
				tc.valid,
				validCookie(tc.secret, tc.cookie, tc.cid, tc.src, tc.now),
			)
		})
	}
}

func TestExpandLabelLayout(t *testing.T) {
	a := require.New(t)
	secret := bytes.Repeat([]byte{3}, 64)
	got, err := expandLabel(secret, "c2s", 32)
	a.NoError(err)
	want, err := hkdf.Expand(
		sha512.New, secret, "\x00\x20\x0ekamune udp c2s\x00", 32,
	)
	a.NoError(err)
	a.Equal(want, got)
}

func TestPathKeyAgreement(t *testing.T) {
	a := require.New(t)
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	a.NoError(err)
	var cookie [cookieLen]byte
	cookie[0] = 1
	m := initMsg{cid: 5, cookie: cookie}
	copy(m.cEph[:], priv.PublicKey().Bytes())

	out, err := responderAccept(m, 6)
	a.NoError(err)
	ac, err := parseAccept(out.pkt)
	a.NoError(err)
	a.Equal(uint32(5), ac.cid)
	a.Equal(uint32(6), ac.sid)

	keys, err := clientKeys(priv, cookie, out.pkt, ac)
	a.NoError(err)
	n := nonce(1)
	sealed := keys.c2s.Seal(nil, n[:], []byte("ping"), nil)
	opened, err := out.keys.c2s.Open(nil, n[:], sealed, nil)
	a.NoError(err)
	a.Equal([]byte("ping"), opened)
	sealed = out.keys.s2c.Seal(nil, n[:], []byte("pong"), nil)
	opened, err = keys.s2c.Open(nil, n[:], sealed, nil)
	a.NoError(err)
	a.Equal([]byte("pong"), opened)

	bad := bytes.Clone(out.pkt)
	bad[AcceptSize-1] ^= 1
	_, err = clientKeys(priv, cookie, bad, ac)
	a.ErrorIs(err, errBadTag)

	// The cookie is in the transcript, so another one changes the keys and
	// the tag no longer verifies.
	other := cookie
	other[1] = 1
	_, err = clientKeys(priv, other, out.pkt, ac)
	a.ErrorIs(err, errBadTag)
}

func TestResponderAcceptSmallOrderKey(t *testing.T) {
	low := [][ephLen]byte{{}, {1}}
	for _, eph := range low {
		a := require.New(t)
		_, err := responderAccept(initMsg{cid: 5, cEph: eph}, 6)
		a.Error(err)
	}
}

func TestRandomIDNonZero(t *testing.T) {
	a := require.New(t)
	seen := make(map[uint32]struct{})
	for range 1000 {
		id := randomID()
		a.NotZero(id)
		seen[id] = struct{}{}
	}
	a.Greater(len(seen), 990)
}
