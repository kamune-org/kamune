package kamune

import (
	"crypto/sha512"
	"encoding/binary"
	"hash"
)

const transcriptPrefix = "kamune/2 transcript"

// transcript is the running SHA-512 of the handshake entries.
type transcript struct {
	h hash.Hash
}

func (t *transcript) hash() hash.Hash {
	if t.h == nil {
		t.h = sha512.New()
		_, _ = t.h.Write([]byte(transcriptPrefix))
	}
	return t.h
}

func (t *transcript) add(tag byte, b []byte) {
	h := t.hash()
	var ln [4]byte
	binary.BigEndian.PutUint32(ln[:], uint32(len(b)))
	_, _ = h.Write([]byte{tag})
	_, _ = h.Write(ln[:])
	_, _ = h.Write(b)
}

func (t *transcript) sum() []byte {
	h := t.hash()
	if c, ok := h.(hash.Cloner); ok {
		cloned, err := c.Clone()
		if err == nil {
			return cloned.Sum(nil)
		}
	}
	return h.Sum(nil)
}
