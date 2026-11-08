package relayleg

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// framedConn is a net.Pipe endpoint with a 2-byte big-endian
// length prefix. It is the in-memory transport for handshake tests.
type framedConn struct {
	c     net.Conn
	limit int
}

func framePair(t *testing.T) (*framedConn, *framedConn) {
	t.Helper()
	left, right := net.Pipe()
	a := &framedConn{c: left, limit: pipeLimit}
	b := &framedConn{c: right, limit: pipeLimit}
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	return a, b
}

func (f *framedConn) ReadBytes() ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(f.c, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	buf := make([]byte, n)
	if _, err := io.ReadFull(f.c, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (f *framedConn) WriteBytes(b []byte) error {
	if len(b) > 0xFFFF {
		return fmt.Errorf("frame is %d bytes", len(b))
	}
	if f.limit > 0 && len(b) > f.limit {
		return fmt.Errorf(
			"%w: %d bytes, limit %d", ErrFrameTooLarge, len(b), f.limit,
		)
	}
	buf := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(b)))
	copy(buf[2:], b)
	n, err := f.c.Write(buf)
	if err != nil {
		return err
	}
	if n != len(buf) {
		return io.ErrShortWrite
	}
	return nil
}

func (f *framedConn) MaxFrameSize() int { return f.limit }

func (f *framedConn) Close() error { return f.c.Close() }

func (f *framedConn) SetDeadline(t time.Time) error {
	return f.c.SetDeadline(t)
}

func (f *framedConn) SetReadDeadline(t time.Time) error {
	return f.c.SetReadDeadline(t)
}

func (f *framedConn) SetWriteDeadline(t time.Time) error {
	return f.c.SetWriteDeadline(t)
}

// scriptRW is a ReadWriter whose reads are a fixed list.
// Writes are recorded. A non-positive limit means no frame limit.
type scriptRW struct {
	reads   [][]byte
	readErr error
	i       int
	writes  [][]byte
	limit   int
	closed  bool
	closes  int
}

func (s *scriptRW) ReadBytes() ([]byte, error) {
	if s.closed {
		return nil, io.ErrClosedPipe
	}
	if s.i >= len(s.reads) {
		if s.readErr != nil {
			return nil, s.readErr
		}
		return nil, io.EOF
	}
	b := s.reads[s.i]
	s.i++
	return b, nil
}

func (s *scriptRW) WriteBytes(b []byte) error {
	if s.closed {
		return io.ErrClosedPipe
	}
	if s.limit > 0 && len(b) > s.limit {
		return fmt.Errorf(
			"%w: %d bytes, limit %d", ErrFrameTooLarge, len(b), s.limit,
		)
	}
	s.writes = append(s.writes, bytes.Clone(b))
	return nil
}

func (s *scriptRW) MaxFrameSize() int { return s.limit }

func (s *scriptRW) Close() error {
	s.closed = true
	s.closes++
	return nil
}

func (s *scriptRW) written() int {
	n := 0
	for _, w := range s.writes {
		n += len(w)
	}
	return n
}

// tap records frames written to a framed connection.
type tap struct {
	*framedConn
	writes [][]byte
}

func (t *tap) WriteBytes(b []byte) error {
	t.writes = append(t.writes, bytes.Clone(b))
	return t.framedConn.WriteBytes(b)
}

func assertNoRecord(t *testing.T, writes [][]byte) {
	t.Helper()
	a := require.New(t)
	for i, w := range writes {
		ok := len(w) >= headerLen &&
			w[0] == magic0 && w[1] == magic1
		a.True(ok, "write %d (%d bytes) is a record", i, len(w))
	}
}

type timeoutError struct{}

func (timeoutError) Error() string { return "timeout" }

func (timeoutError) Timeout() bool { return true }

type failConn struct {
	err    error
	writes int
	closes int
}

func (f *failConn) ReadBytes() ([]byte, error) { return nil, io.EOF }

func (f *failConn) WriteBytes([]byte) error {
	f.writes++
	return f.err
}

func (f *failConn) Close() error {
	f.closes++
	return nil
}

func (f *failConn) MaxFrameSize() int { return 0 }
