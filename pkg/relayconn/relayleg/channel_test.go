package relayleg

import (
	"bytes"
	"errors"
	"io"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func testKeys(t *testing.T) recordKeys {
	t.Helper()
	a := require.New(t)
	ch := make([]byte, sizeClientHello)
	sh := make([]byte, sizeServerHello)
	putHeader(ch, typeClientHello)
	putHeader(sh, typeServerHello)
	var pk PublicKey
	for i := range pk {
		pk[i] = byte(i + 1)
	}
	ss := bytes.Repeat([]byte{9}, ssLen)
	se := bytes.Repeat([]byte{8}, ssLen)
	_, _, _, keys, err := schedule(nil, pk, ch, sh, ss, se)
	a.NoError(err)
	return keys
}

func sealRecords(t *testing.T, pts [][]byte) (recordKeys, [][]byte) {
	t.Helper()
	a := require.New(t)
	base := testKeys(t)
	k := base
	w := &scriptRW{}
	ch, err := newChannel(w, &k, true)
	a.NoError(err)
	for _, p := range pts {
		a.NoError(ch.WriteBytes(p))
	}
	return base, w.writes
}

func TestRecordRoundTrip(t *testing.T) {
	a := require.New(t)
	pts := [][]byte{
		[]byte("one"),
		[]byte("two"),
		{},
	}
	keys, cts := sealRecords(t, pts)
	k := keys
	r := &scriptRW{reads: cts}
	ch, err := newChannel(r, &k, false)
	a.NoError(err)
	for _, want := range pts {
		got, err := ch.ReadBytes()
		a.NoError(err)
		// Open yields nil for an empty plaintext.
		a.True(bytes.Equal(want, got))
	}
}

func TestRecordTamper(t *testing.T) {
	pts := [][]byte{[]byte("one"), []byte("two"), []byte("three")}
	keys, cts := sealRecords(t, pts)

	t.Run("reorder", func(t *testing.T) {
		a := require.New(t)
		k := keys
		r := &scriptRW{reads: [][]byte{cts[1], cts[0]}}
		ch, err := newChannel(r, &k, false)
		a.NoError(err)
		_, err = ch.ReadBytes()
		a.ErrorIs(err, ErrRecordAuth)
	})

	t.Run("replay", func(t *testing.T) {
		a := require.New(t)
		k := keys
		r := &scriptRW{reads: [][]byte{cts[0], cts[0]}}
		ch, err := newChannel(r, &k, false)
		a.NoError(err)
		got, err := ch.ReadBytes()
		a.NoError(err)
		a.Equal(pts[0], got)
		_, err = ch.ReadBytes()
		a.ErrorIs(err, ErrRecordAuth)
	})

	t.Run("bit flip", func(t *testing.T) {
		a := require.New(t)
		bad := bytes.Clone(cts[0])
		bad[0] ^= 0x01
		k := keys
		r := &scriptRW{reads: [][]byte{bad}}
		ch, err := newChannel(r, &k, false)
		a.NoError(err)
		_, err = ch.ReadBytes()
		a.ErrorIs(err, ErrRecordAuth)
	})

	t.Run("drop middle", func(t *testing.T) {
		a := require.New(t)
		k := keys
		r := &scriptRW{reads: [][]byte{cts[0], cts[2]}}
		ch, err := newChannel(r, &k, false)
		a.NoError(err)
		got, err := ch.ReadBytes()
		a.NoError(err)
		a.Equal(pts[0], got)
		_, err = ch.ReadBytes()
		a.ErrorIs(err, ErrRecordAuth)
	})
}

func TestWriteFailureSticky(t *testing.T) {
	a := require.New(t)
	k := testKeys(t)
	f := &failConn{err: errors.New("boom")}
	ch, err := newChannel(f, &k, true)
	a.NoError(err)
	err = ch.WriteBytes([]byte("x"))
	a.ErrorIs(err, ErrChannelBroken)
	a.Equal(1, f.writes)
	a.Equal(1, f.closes)
	err = ch.WriteBytes([]byte("y"))
	a.ErrorIs(err, ErrChannelBroken)
	a.Equal(1, f.writes)
	a.Equal(1, f.closes)
}

func TestOversizeStaysUsable(t *testing.T) {
	a := require.New(t)
	k := testKeys(t)
	rw := &scriptRW{limit: 32}
	ch, err := newChannel(rw, &k, true)
	a.NoError(err)
	a.Equal(16, ch.MaxFrameSize())
	err = ch.WriteBytes(make([]byte, 17))
	a.ErrorIs(err, ErrFrameTooLarge)
	a.Empty(rw.writes)
	a.NoError(ch.WriteBytes(make([]byte, 16)))
	a.Len(rw.writes, 1)
	a.NoError(ch.WriteBytes([]byte("still")))
	a.Len(rw.writes, 2)
}

func TestSequenceExhaustion(t *testing.T) {
	t.Run("at max", func(t *testing.T) {
		a := require.New(t)
		k := testKeys(t)
		rw := &scriptRW{}
		ch, err := newChannel(rw, &k, true)
		a.NoError(err)
		ch.setSendSeq(math.MaxUint64)
		err = ch.WriteBytes([]byte{1})
		a.ErrorIs(err, ErrChannelBroken)
		a.Empty(rw.writes)
		a.Equal(1, rw.closes)
		err = ch.WriteBytes([]byte{2})
		a.ErrorIs(err, ErrChannelBroken)
		a.Empty(rw.writes)
		a.Equal(1, rw.closes)
	})

	t.Run("last value", func(t *testing.T) {
		a := require.New(t)
		k := testKeys(t)
		rw := &scriptRW{}
		ch, err := newChannel(rw, &k, true)
		a.NoError(err)
		ch.setSendSeq(math.MaxUint64 - 1)
		a.NoError(ch.WriteBytes([]byte{1}))
		a.Len(rw.writes, 1)
		err = ch.WriteBytes([]byte{2})
		a.ErrorIs(err, ErrChannelBroken)
		a.Len(rw.writes, 1)
	})
}

func TestMaxFrameSize(t *testing.T) {
	a := require.New(t)
	tests := []struct {
		limit int
		want  int
	}{
		{limit: 0, want: 0},
		{limit: -5, want: 0},
		{limit: 1, want: 1},
		{limit: 16, want: 1},
		{limit: 17, want: 1},
		{limit: 100, want: 84},
	}
	for _, tt := range tests {
		k := testKeys(t)
		rw := &scriptRW{limit: tt.limit}
		ch, err := newChannel(rw, &k, true)
		a.NoError(err)
		a.Equal(tt.want, ch.MaxFrameSize())
	}
	k := testKeys(t)
	ch, err := newChannel(bareConn{}, &k, true)
	a.NoError(err)
	a.Equal(0, ch.MaxFrameSize())
}

type bareConn struct{}

func (bareConn) ReadBytes() ([]byte, error) { return nil, io.EOF }

func (bareConn) WriteBytes([]byte) error { return nil }

type deadConn struct {
	scriptRW
	sets int
}

func (d *deadConn) SetWriteDeadline(time.Time) error {
	d.sets++
	return nil
}

func TestWriteBytesWithinDeadline(t *testing.T) {
	a := require.New(t)
	d := &deadConn{}
	k := testKeys(t)
	ch, err := newChannel(d, &k, true)
	a.NoError(err)
	a.NoError(ch.WriteBytesWithin([]byte("a"), time.Second))
	a.Equal(2, d.sets)
	d.sets = 0
	a.NoError(ch.WriteBytes([]byte("b")))
	a.Zero(d.sets)
}
