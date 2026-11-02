package udppath

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	cookieLabel = "kamune udp cookie v1"
	knockLabel  = "kamune udp knock v1"
	pathLabel   = "kamune udp path v1"

	// labelPrefix starts every ExpandLabel label. The label "binding" is
	// reserved for a later channel binding and is not derived.
	labelPrefix = "kamune udp "

	keyLen = chacha20poly1305.KeySize

	// cookieSkew is how far a cookie time may be ahead of the server clock.
	cookieSkew = time.Second
)

// errBadTag is an ACCEPT whose tag does not verify.
var errBadTag = errors.New("udp path: bad tag")

// pathKeys are the AEADs of one path, one per direction.
type pathKeys struct {
	c2s cipher.AEAD
	s2c cipher.AEAD
}

// acceptOut is the server's half of a completed INIT: the keys of the new
// path and the ACCEPT that confirms them.
type acceptOut struct {
	keys pathKeys
	pkt  []byte
}

// cookieMAC is the MAC half of a cookie. It binds the time, the client id
// and the source address and port; IPv4 and IPv4-mapped IPv6 give the same
// input.
func cookieMAC(
	secret []byte, t, cid uint32, src netip.AddrPort,
) [macLen]byte {
	var in [len(cookieLabel) + 4 + 4 + 16 + 2]byte
	n := copy(in[:], cookieLabel)
	binary.BigEndian.PutUint32(in[n:], t)
	n += 4
	binary.BigEndian.PutUint32(in[n:], cid)
	n += 4
	addr := src.Addr().Unmap().As16()
	n += copy(in[n:], addr[:])
	binary.BigEndian.PutUint16(in[n:], src.Port())

	m := hmac.New(sha256.New, secret)
	_, _ = m.Write(in[:])
	var out [macLen]byte
	copy(out[:], m.Sum(nil))
	return out
}

// makeCookie returns the cookie t || mac for cid and src at now.
func makeCookie(
	secret []byte, now time.Time, cid uint32, src netip.AddrPort,
) [cookieLen]byte {
	var c [cookieLen]byte
	t := uint32(now.Unix())
	binary.BigEndian.PutUint32(c[:], t)
	mac := cookieMAC(secret, t, cid, src)
	copy(c[4:], mac[:])
	return c
}

// validCookie reports whether cookie was made by secret for cid and src no
// more than [CookieLifetime] before now and no more than one second after.
func validCookie(
	secret []byte,
	cookie [cookieLen]byte,
	cid uint32,
	src netip.AddrPort,
	now time.Time,
) bool {
	t := binary.BigEndian.Uint32(cookie[:])
	age := now.Unix() - int64(t)
	if age < -int64(cookieSkew/time.Second) ||
		age > int64(CookieLifetime/time.Second) {
		return false
	}
	want := cookieMAC(secret, t, cid, src)
	return hmac.Equal(cookie[4:], want[:])
}

// knockMAC is mac1 over covered: bytes 0-7 of a HELLO, or 0-59 of an INIT.
func knockMAC(key, covered []byte) [macLen]byte {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write([]byte(knockLabel))
	_, _ = m.Write(covered)
	var out [macLen]byte
	copy(out[:], m.Sum(nil))
	return out
}

// checkKnock reports whether mac1 is right for covered. Without a key every
// mac1 passes.
func checkKnock(key []byte, mac1 [macLen]byte, covered []byte) bool {
	if key == nil {
		return true
	}
	want := knockMAC(key, covered)
	return hmac.Equal(mac1[:], want[:])
}

// pathTranscript hashes the values both ends agree on in INIT and ACCEPT.
func pathTranscript(
	cid uint32, cookie [cookieLen]byte, cEph []byte, sid uint32, sEph []byte,
) []byte {
	h := sha512.New()
	var id [4]byte
	_, _ = h.Write([]byte(pathLabel))
	binary.BigEndian.PutUint32(id[:], cid)
	_, _ = h.Write(id[:])
	_, _ = h.Write(cookie[:])
	_, _ = h.Write(cEph)
	binary.BigEndian.PutUint32(id[:], sid)
	_, _ = h.Write(id[:])
	_, _ = h.Write(sEph)
	return h.Sum(nil)
}

// expandLabel is HKDF-Expand with the TLS 1.3 HkdfLabel layout and an empty
// context: uint16(n) || uint8(len(l)) || l || 0x00.
func expandLabel(secret []byte, label string, n int) ([]byte, error) {
	l := labelPrefix + label
	info := make([]byte, 0, 4+len(l))
	info = append(info, byte(n>>8), byte(n), byte(len(l)))
	info = append(info, l...)
	info = append(info, 0)
	return hkdf.Expand(sha512.New, secret, string(info), n)
}

// deriveKeys turns the X25519 output and the transcript hash into the path
// keys.
func deriveKeys(shared, th []byte) (pathKeys, error) {
	var keys pathKeys
	prk, err := hkdf.Extract(sha512.New, shared, th)
	if err != nil {
		return keys, fmt.Errorf("udp path keys: %w", err)
	}
	c2s, err := expandLabel(prk, "c2s", keyLen)
	if err != nil {
		return keys, fmt.Errorf("udp path keys: %w", err)
	}
	s2c, err := expandLabel(prk, "s2c", keyLen)
	if err != nil {
		return keys, fmt.Errorf("udp path keys: %w", err)
	}
	if keys.c2s, err = chacha20poly1305.New(c2s); err != nil {
		return keys, fmt.Errorf("udp path keys: %w", err)
	}
	if keys.s2c, err = chacha20poly1305.New(s2c); err != nil {
		return keys, fmt.Errorf("udp path keys: %w", err)
	}
	return keys, nil
}

// nonce is 0x00000000 || uint64be(ctr). Counter 0 under the server-to-client
// key is the ACCEPT tag's nonce.
func nonce(ctr uint64) [chacha20poly1305.NonceSize]byte {
	var n [chacha20poly1305.NonceSize]byte
	binary.BigEndian.PutUint64(n[4:], ctr)
	return n
}

// sealAccept fills the tag of an ACCEPT built by encodeAcceptBody.
func sealAccept(pkt []byte, s2c cipher.AEAD) {
	n := nonce(0)
	tag := s2c.Seal(nil, n[:], nil, pkt[:acceptTag])
	copy(pkt[acceptTag:], tag)
}

// openAccept reports whether the tag of the ACCEPT pkt verifies.
func openAccept(pkt []byte, s2c cipher.AEAD) bool {
	n := nonce(0)
	_, err := s2c.Open(nil, n[:], pkt[acceptTag:], pkt[:acceptTag])
	return err == nil
}

// responderAccept runs the server's side of INIT m for the server id sid:
// a fresh ephemeral key, X25519 with the client's, the path keys and the
// sealed ACCEPT. It fails for a client key whose X25519 output is all zero.
func responderAccept(m initMsg, sid uint32) (acceptOut, error) {
	curve := ecdh.X25519()
	peer, err := curve.NewPublicKey(m.cEph[:])
	if err != nil {
		return acceptOut{}, fmt.Errorf("udp path client key: %w", err)
	}
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return acceptOut{}, fmt.Errorf("udp path server key: %w", err)
	}
	shared, err := priv.ECDH(peer)
	if err != nil {
		return acceptOut{}, fmt.Errorf("udp path x25519: %w", err)
	}
	sEph := priv.PublicKey().Bytes()
	th := pathTranscript(m.cid, m.cookie, m.cEph[:], sid, sEph)
	keys, err := deriveKeys(shared, th)
	if err != nil {
		return acceptOut{}, err
	}
	pkt := encodeAcceptBody(m.cid, sid, sEph)
	sealAccept(pkt, keys.s2c)
	return acceptOut{keys: keys, pkt: pkt}, nil
}

// clientKeys runs the dialer's side of the ACCEPT pkt, parsed as m, and
// returns the path keys once its tag verifies.
func clientKeys(
	priv *ecdh.PrivateKey,
	cookie [cookieLen]byte,
	pkt []byte,
	m acceptMsg,
) (pathKeys, error) {
	peer, err := ecdh.X25519().NewPublicKey(m.sEph[:])
	if err != nil {
		return pathKeys{}, fmt.Errorf("udp path server key: %w", err)
	}
	shared, err := priv.ECDH(peer)
	if err != nil {
		return pathKeys{}, fmt.Errorf("udp path x25519: %w", err)
	}
	th := pathTranscript(
		m.cid, cookie, priv.PublicKey().Bytes(), m.sid, m.sEph[:],
	)
	keys, err := deriveKeys(shared, th)
	if err != nil {
		return pathKeys{}, err
	}
	if !openAccept(pkt, keys.s2c) {
		return pathKeys{}, errBadTag
	}
	return keys, nil
}

// randomID returns a random non-zero 32-bit id.
func randomID() uint32 {
	var b [4]byte
	for {
		_, _ = rand.Read(b[:])
		if id := binary.BigEndian.Uint32(b[:]); id != 0 {
			return id
		}
	}
}
