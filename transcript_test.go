package kamune

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTranscript_Order(t *testing.T) {
	a := require.New(t)
	var tr transcript
	tr.add(0x01, []byte("hello"))
	first := tr.sum()

	var prefix []byte
	prefix = append(prefix, "kamune/2 transcript"...)
	prefix = append(prefix, 0x01)
	var ln [4]byte
	binary.BigEndian.PutUint32(ln[:], uint32(len("hello")))
	prefix = append(prefix, ln[:]...)
	prefix = append(prefix, "hello"...)
	want := sha512.Sum512(prefix)
	a.Equal(want[:], first)

	tr.add(0x02, []byte("world"))
	second := tr.sum()
	a.NotEqual(first, second)

	var changed transcript
	changed.add(0x01, []byte("HELLO"))
	changed.add(0x02, []byte("world"))
	a.NotEqual(second, changed.sum())

	var later transcript
	later.add(0x01, []byte("hello"))
	later.add(0x02, []byte("WORLD"))
	a.NotEqual(second, later.sum())
	a.NotEqual(first, later.sum())

	a.False(bytes.Equal(first, second))
}
