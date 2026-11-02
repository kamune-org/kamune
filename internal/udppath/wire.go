package udppath

import (
	"encoding/binary"
	"errors"
)

// Packet types. Every packet starts with type, version and two reserved
// zero bytes.
const (
	typeHello  = 0x01
	typeCookie = 0x02
	typeInit   = 0x03
	typeAccept = 0x04
)

// Field sizes.
const (
	headerLen = 4
	macLen    = 16
	cookieLen = 20 // t || mac
	ephLen    = 32
)

// Field offsets within HELLO, INIT and ACCEPT. Each field runs to the next
// offset.
const (
	helloMAC1  = 8
	helloPad   = 24
	initCookie = 8
	initEph    = 28
	initMAC1   = 60
	initPad    = 76
	acceptSID  = 8
	acceptEph  = 12
	acceptTag  = 44
)

// errMalformed is a packet that fails the length, header, id or padding
// checks. The receiver drops it without a reply.
var errMalformed = errors.New("malformed udp path packet")

type helloMsg struct {
	mac1 [macLen]byte
	cid  uint32
}

type cookieMsg struct {
	cookie [cookieLen]byte
	cid    uint32
}

type initMsg struct {
	cookie [cookieLen]byte
	cEph   [ephLen]byte
	mac1   [macLen]byte
	cid    uint32
}

type acceptMsg struct {
	sEph [ephLen]byte
	tag  [macLen]byte
	cid  uint32
	sid  uint32
}

func putHeader(b []byte, typ byte) {
	b[0], b[1], b[2], b[3] = typ, Version, 0, 0
}

// checkHeader checks the exact size and the header of pkt.
func checkHeader(pkt []byte, typ byte, size int) error {
	if len(pkt) != size || pkt[0] != typ || pkt[1] != Version ||
		pkt[2] != 0 || pkt[3] != 0 {
		return errMalformed
	}
	return nil
}

// readID returns the non-zero id at b[0:4].
func readID(b []byte) (uint32, error) {
	id := binary.BigEndian.Uint32(b)
	if id == 0 {
		return 0, errMalformed
	}
	return id, nil
}

// encodeHello returns a HELLO for cid. With a knock key it fills mac1.
func encodeHello(cid uint32, knock []byte) []byte {
	b := make([]byte, HelloSize)
	putHeader(b, typeHello)
	binary.BigEndian.PutUint32(b[4:], cid)
	if knock != nil {
		mac := knockMAC(knock, b[:helloMAC1])
		copy(b[helloMAC1:], mac[:])
	}
	return b
}

func parseHello(pkt []byte) (helloMsg, error) {
	var m helloMsg
	if err := checkHeader(pkt, typeHello, HelloSize); err != nil {
		return m, err
	}
	cid, err := readID(pkt[4:])
	if err != nil {
		return m, err
	}
	if !allZero(pkt[helloPad:]) {
		return m, errMalformed
	}
	m.cid = cid
	copy(m.mac1[:], pkt[helloMAC1:helloPad])
	return m, nil
}

func encodeCookie(cid uint32, cookie [cookieLen]byte) []byte {
	b := make([]byte, CookieSize)
	putHeader(b, typeCookie)
	binary.BigEndian.PutUint32(b[4:], cid)
	copy(b[8:], cookie[:])
	return b
}

func parseCookie(pkt []byte) (cookieMsg, error) {
	var m cookieMsg
	if err := checkHeader(pkt, typeCookie, CookieSize); err != nil {
		return m, err
	}
	cid, err := readID(pkt[4:])
	if err != nil {
		return m, err
	}
	m.cid = cid
	copy(m.cookie[:], pkt[8:])
	return m, nil
}

// encodeInit returns an INIT for cid with the cookie and the client's
// ephemeral public key. With a knock key it fills mac1.
func encodeInit(
	cid uint32, cookie [cookieLen]byte, cEph []byte, knock []byte,
) []byte {
	b := make([]byte, InitSize)
	putHeader(b, typeInit)
	binary.BigEndian.PutUint32(b[4:], cid)
	copy(b[initCookie:initEph], cookie[:])
	copy(b[initEph:initMAC1], cEph)
	if knock != nil {
		mac := knockMAC(knock, b[:initMAC1])
		copy(b[initMAC1:], mac[:])
	}
	return b
}

func parseInit(pkt []byte) (initMsg, error) {
	var m initMsg
	if err := checkHeader(pkt, typeInit, InitSize); err != nil {
		return m, err
	}
	cid, err := readID(pkt[4:])
	if err != nil {
		return m, err
	}
	if !allZero(pkt[initPad:]) {
		return m, errMalformed
	}
	m.cid = cid
	copy(m.cookie[:], pkt[initCookie:initEph])
	copy(m.cEph[:], pkt[initEph:initMAC1])
	copy(m.mac1[:], pkt[initMAC1:initPad])
	return m, nil
}

// encodeAcceptBody returns an ACCEPT whose tag is still zero. sealAccept
// fills the tag.
func encodeAcceptBody(cid, sid uint32, sEph []byte) []byte {
	b := make([]byte, AcceptSize)
	putHeader(b, typeAccept)
	binary.BigEndian.PutUint32(b[4:], cid)
	binary.BigEndian.PutUint32(b[acceptSID:], sid)
	copy(b[acceptEph:acceptTag], sEph)
	return b
}

func parseAccept(pkt []byte) (acceptMsg, error) {
	var m acceptMsg
	if err := checkHeader(pkt, typeAccept, AcceptSize); err != nil {
		return m, err
	}
	cid, err := readID(pkt[4:])
	if err != nil {
		return m, err
	}
	sid, err := readID(pkt[acceptSID:])
	if err != nil {
		return m, err
	}
	m.cid, m.sid = cid, sid
	copy(m.sEph[:], pkt[acceptEph:acceptTag])
	copy(m.tag[:], pkt[acceptTag:])
	return m, nil
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
