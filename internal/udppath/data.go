package udppath

import (
	"crypto/cipher"
	"encoding/binary"
)

const (
	// sealedHeaderLen is the clear part of a DATA or CLOSE: the header, rid
	// and ctr. It is the AEAD's additional data, type byte included, so a
	// DATA cannot be turned into a CLOSE.
	sealedHeaderLen = 16
	sealedCtr       = 8
)

// sealedMsg is the clear header of a DATA or CLOSE.
type sealedMsg struct {
	ctr uint64
	rid uint32
	typ byte
}

// parseSealed checks a DATA or CLOSE and returns its clear header. It
// rejects counter 0, which is the ACCEPT tag's nonce, and counters of 2^63
// and above.
func parseSealed(pkt []byte) (sealedMsg, error) {
	var m sealedMsg
	if len(pkt) < headerLen {
		return m, errMalformed
	}
	switch pkt[0] {
	case typeData:
		if len(pkt) <= DataOverhead || len(pkt) > MaxDatagram {
			return m, errMalformed
		}
	case typeClose:
		if len(pkt) != CloseSize {
			return m, errMalformed
		}
	default:
		return m, errMalformed
	}
	if err := checkHeader(pkt, pkt[0], len(pkt)); err != nil {
		return m, err
	}
	rid, err := readID(pkt[4:])
	if err != nil {
		return m, err
	}
	ctr := binary.BigEndian.Uint64(pkt[sealedCtr:])
	if ctr == 0 || ctr >= maxCounter {
		return m, errMalformed
	}
	m.typ, m.rid, m.ctr = pkt[0], rid, ctr
	return m, nil
}

// sealPacket appends a DATA (typeData, payload of 1 to KCPMTU bytes) or a
// CLOSE (typeClose, no payload) to dst[:0] and returns it. dst needs room
// for len(payload) + DataOverhead bytes, or Seal allocates.
func sealPacket(
	dst []byte,
	aead cipher.AEAD,
	typ byte,
	rid uint32,
	ctr uint64,
	payload []byte,
) []byte {
	if cap(dst) < sealedHeaderLen {
		dst = make([]byte, 0, len(payload)+DataOverhead)
	}
	dst = dst[:sealedHeaderLen]
	putHeader(dst, typ)
	binary.BigEndian.PutUint32(dst[4:], rid)
	binary.BigEndian.PutUint64(dst[sealedCtr:], ctr)
	n := nonce(ctr)
	// Seal appends after the header, so its output never overlaps the
	// header it reads as additional data.
	return aead.Seal(dst, n[:], payload, dst)
}

// openPacket opens the sealed part of pkt with counter ctr into dst[:0].
func openPacket(
	dst []byte, aead cipher.AEAD, ctr uint64, pkt []byte,
) ([]byte, error) {
	n := nonce(ctr)
	return aead.Open(
		dst[:0], n[:], pkt[sealedHeaderLen:], pkt[:sealedHeaderLen],
	)
}
