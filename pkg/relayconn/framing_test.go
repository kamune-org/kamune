package relayconn

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFraming_ReadWriteRoundtrip(t *testing.T) {
	a := require.New(t)
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	fA := NewFraming(c, 0)
	fB := NewFraming(s, 0)

	want := []byte("hello from a")

	writeErr := make(chan error, 1)
	go func() {
		writeErr <- fA.WriteBytes(want)
	}()

	got, err := fB.ReadBytes()
	a.NoError(err)
	a.Equal(want, got)
	a.NoError(<-writeErr)
}

func TestFraming_EmptyFrame(t *testing.T) {
	a := require.New(t)
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	fA := NewFraming(c, 0)
	fB := NewFraming(s, 0)

	go func() { _ = fA.WriteBytes(nil) }()

	got, err := fB.ReadBytes()
	a.NoError(err)
	a.Empty(got)
}

func TestFraming_MaxSizeEnforced(t *testing.T) {
	a := require.New(t)
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	fB := NewFraming(s, 10)

	go func() {
		_ = binary.Write(c, binary.BigEndian, uint16(100))
		_, _ = c.Write(make([]byte, 100))
	}()

	_, err := fB.ReadBytes()
	a.Error(err)
	a.Contains(err.Error(), "exceeds max")
}

func TestFraming_NoMaxSize(t *testing.T) {
	a := require.New(t)
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	fA := NewFraming(c, 0)
	fB := NewFraming(s, 0)

	want := bytes.Repeat([]byte("x"), 60000)

	go func() { _ = fA.WriteBytes(want) }()

	got, err := fB.ReadBytes()
	a.NoError(err)
	a.Equal(want, got)
}

func TestFraming_WriteBytesRejectsOverflow(t *testing.T) {
	a := require.New(t)
	f := NewFraming(&partialReadWriteCloser{maxWrite: 1}, 0)

	err := f.WriteBytes(make([]byte, math.MaxUint16+1))
	a.Error(err)
	a.Contains(err.Error(), "exceeds maximum")
}

func TestFraming_WriteBytesCompletesPartialWrites(t *testing.T) {
	a := require.New(t)
	rwc := &partialReadWriteCloser{maxWrite: 1}
	f := NewFraming(rwc, 0)

	a.NoError(f.WriteBytes([]byte("hello")))
	a.Equal([]byte{0, 5, 'h', 'e', 'l', 'l', 'o'}, rwc.Bytes())
}

func TestFraming_TruncatedFrame(t *testing.T) {
	a := require.New(t)
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	fB := NewFraming(s, 0)

	go func() {
		defer c.Close()
		_, _ = c.Write([]byte{0x00, 0x64}) // length = 100
		_, _ = c.Write([]byte{1, 2, 3, 4, 5})
	}()

	_, err := fB.ReadBytes()
	a.Error(err)
	a.True(
		errors.Is(err, io.ErrUnexpectedEOF) || bytes.Contains([]byte(err.Error()), []byte("read data")),
		"err = %v, want io.ErrUnexpectedEOF or 'read data'", err,
	)
}

func TestFraming_Close(t *testing.T) {
	a := require.New(t)
	c, s := net.Pipe()
	defer s.Close()

	fA := NewFraming(c, 0)
	a.NoError(fA.Close())
	err := fA.WriteBytes([]byte("x"))
	a.Error(err)
}

func TestFraming_SetDeadline_Delegates(t *testing.T) {
	a := require.New(t)
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	fA := NewFraming(c, 0)
	a.NoError(fA.SetDeadline(time.Time{}))
}

func TestFraming_SetDeadline_NoOp(t *testing.T) {
	a := require.New(t)
	rwc := struct {
		io.ReadWriter
		io.Closer
	}{}

	f := NewFraming(rwc, 0)
	a.NoError(f.SetDeadline(time.Time{}))
}

func TestFraming_SetWriteDeadline_Delegates(t *testing.T) {
	a := require.New(t)
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()

	f := NewFraming(c, 0)
	a.NoError(f.SetWriteDeadline(time.Now().Add(-time.Second)))
	err := f.WriteBytes([]byte("blocked"))
	a.ErrorIs(err, os.ErrDeadlineExceeded)
}

func TestFraming_SetWriteDeadline_NoOp(t *testing.T) {
	a := require.New(t)
	rwc := struct {
		io.ReadWriter
		io.Closer
	}{}

	f := NewFraming(rwc, 0)
	a.NoError(f.SetWriteDeadline(time.Time{}))
}

type partialReadWriteCloser struct {
	bytes.Buffer
	maxWrite int
}

func (c *partialReadWriteCloser) Write(data []byte) (int, error) {
	if len(data) > c.maxWrite {
		data = data[:c.maxWrite]
	}
	return c.Buffer.Write(data)
}

func (*partialReadWriteCloser) Close() error { return nil }
