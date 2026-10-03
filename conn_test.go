package kamune

import (
	"bytes"
	"errors"
	"math"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/pkg/exchange"
)

var (
	_ net.Conn              = new(conn)
	_ Conn                  = new(conn)
	_ exchange.FrameLimiter = new(conn)
)

func TestConn_WriteBytes_RejectsOverflow(t *testing.T) {
	a := require.New(t)
	c1, c2 := net.Pipe()
	defer func() { _ = c1.Close() }()
	defer func() { _ = c2.Close() }()
	conn := newConn(c1)

	// math.MaxUint16 is the framing's hard upper bound; payloads that would
	// overflow the uint16 length prefix must be rejected before any bytes are
	// written to the underlying conn.
	oversize := bytes.Repeat([]byte{0xAB}, math.MaxUint16+1)
	err := conn.WriteBytes(oversize)
	a.Error(err)
	a.True(errors.Is(err, ErrMessageTooLarge))
}

func TestConn_ReadTimeoutRefreshesPerFrame(t *testing.T) {
	a := require.New(t)
	left, right := net.Pipe()
	t.Cleanup(func() {
		_ = left.Close()
		_ = right.Close()
	})

	reader := newConn(left, ConnWithReadTimeout(500*time.Millisecond))
	writer := newConn(right, ConnWithWriteTimeout(time.Second))
	writeErr := make(chan error, 1)
	go func() {
		if err := writer.WriteBytes([]byte("first")); err != nil {
			writeErr <- err
			return
		}
		time.Sleep(650 * time.Millisecond)
		writeErr <- writer.WriteBytes([]byte("second"))
	}()

	first, err := reader.ReadBytes()
	a.NoError(err)
	a.Equal([]byte("first"), first)
	time.Sleep(300 * time.Millisecond)
	second, err := reader.ReadBytes()
	a.NoError(err)
	a.Equal([]byte("second"), second)
	a.NoError(<-writeErr)
}

func TestConn_WriteTimeoutRefreshesPerFrame(t *testing.T) {
	a := require.New(t)
	left, right := net.Pipe()
	t.Cleanup(func() {
		_ = left.Close()
		_ = right.Close()
	})

	writer := newConn(left, ConnWithWriteTimeout(500*time.Millisecond))
	reader := newConn(right, ConnWithReadTimeout(time.Second))
	readErr := make(chan error, 1)
	go func() {
		first, err := reader.ReadBytes()
		if err != nil {
			readErr <- err
			return
		}
		if !bytes.Equal(first, []byte("first")) {
			readErr <- errors.New("unexpected first frame")
			return
		}
		time.Sleep(650 * time.Millisecond)
		second, err := reader.ReadBytes()
		if err != nil {
			readErr <- err
			return
		}
		if !bytes.Equal(second, []byte("second")) {
			readErr <- errors.New("unexpected second frame")
			return
		}
		readErr <- nil
	}()

	a.NoError(writer.WriteBytes([]byte("first")))
	time.Sleep(300 * time.Millisecond)
	a.NoError(writer.WriteBytes([]byte("second")))
	a.NoError(<-readErr)
}

func TestConn_ExplicitDeadlineSurvivesAutomaticTimeout(t *testing.T) {
	a := require.New(t)
	left, right := net.Pipe()
	t.Cleanup(func() {
		_ = left.Close()
		_ = right.Close()
	})

	reader := newConn(left, ConnWithReadTimeout(time.Second))
	a.NoError(reader.SetDeadline(time.Now().Add(50 * time.Millisecond)))

	start := time.Now()
	_, err := reader.ReadBytes()
	a.Error(err)
	a.Less(time.Since(start), 500*time.Millisecond)
}

func TestConn_SetDeadlineInterruptsBlockedRead(t *testing.T) {
	a := require.New(t)
	left, right := net.Pipe()
	t.Cleanup(func() {
		_ = left.Close()
		_ = right.Close()
	})

	reader := newConn(left)
	readErr := make(chan error, 1)
	go func() {
		_, err := reader.ReadBytes()
		readErr <- err
	}()

	time.Sleep(20 * time.Millisecond)
	a.NoError(reader.SetDeadline(time.Now().Add(20 * time.Millisecond)))
	select {
	case err := <-readErr:
		a.Error(err)
	case <-time.After(time.Second):
		t.Fatal("SetDeadline did not interrupt the blocked read")
	}
}

// scriptedConn is a net.Conn whose reads return the queued chunks and, once
// they run out, a read deadline error, as if the deadline had fired. Writes
// accept up to writable bytes in total and then fail the same way.
type scriptedConn struct {
	net.Conn
	chunks   [][]byte
	wrote    []byte
	writable int
	closed   bool
}

func (c *scriptedConn) Read(b []byte) (int, error) {
	if c.closed {
		return 0, net.ErrClosed
	}
	if len(c.chunks) == 0 {
		return 0, os.ErrDeadlineExceeded
	}
	n := copy(b, c.chunks[0])
	c.chunks[0] = c.chunks[0][n:]
	if len(c.chunks[0]) == 0 {
		c.chunks = c.chunks[1:]
	}
	return n, nil
}

func (c *scriptedConn) Write(b []byte) (int, error) {
	if c.closed {
		return 0, net.ErrClosed
	}
	n := min(len(b), c.writable)
	c.wrote = append(c.wrote, b[:n]...)
	c.writable -= n
	if n < len(b) {
		return n, os.ErrDeadlineExceeded
	}
	return n, nil
}

func (*scriptedConn) SetReadDeadline(time.Time) error  { return nil }
func (*scriptedConn) SetWriteDeadline(time.Time) error { return nil }
func (*scriptedConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptedConn) Close() error {
	c.closed = true
	return nil
}

// TestConn_ReadTimeoutMidFrameIsFatal checks that a read deadline that fires
// before a frame starts is a retryable timeout, while one that fires after
// part of a frame was consumed closes the conn.
func TestConn_ReadTimeoutMidFrameIsFatal(t *testing.T) {
	cases := []struct {
		name    string
		partial []byte
		fatal   bool
	}{
		{name: "before frame", partial: nil, fatal: false},
		{name: "inside length prefix", partial: []byte{0}, fatal: true},
		{name: "after length prefix", partial: []byte{0, 10}, fatal: true},
		{name: "inside body", partial: []byte{0, 10, 1, 2, 3}, fatal: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			sc := &scriptedConn{}
			if len(tc.partial) > 0 {
				sc.chunks = [][]byte{tc.partial}
			}
			reader := newConn(sc)

			_, err := reader.ReadBytes()
			a.Error(err)
			if !tc.fatal {
				a.True(isTimeout(err))
				a.NotErrorIs(err, ErrConnClosed)
				a.False(sc.closed)

				sc.chunks = [][]byte{{0, 2, 'o', 'k'}}
				got, err := reader.ReadBytes()
				a.NoError(err)
				a.Equal([]byte("ok"), got)
				return
			}
			a.ErrorIs(err, ErrConnClosed)
			a.False(isTimeout(err))
			a.True(sc.closed)
			_, err = reader.ReadBytes()
			a.ErrorIs(err, ErrConnClosed)
		})
	}
}

// TestConn_WriteTimeoutMidFrameIsFatal checks that a write deadline that
// fires before any byte of a frame is written is a retryable timeout, while
// one that fires after part of a frame was written closes the conn.
func TestConn_WriteTimeoutMidFrameIsFatal(t *testing.T) {
	cases := []struct {
		name     string
		writable int
		fatal    bool
	}{
		{name: "before frame", writable: 0, fatal: false},
		{name: "inside length prefix", writable: 1, fatal: true},
		{name: "after length prefix", writable: 2, fatal: true},
		{name: "inside body", writable: 5, fatal: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			sc := &scriptedConn{writable: tc.writable}
			writer := newConn(sc)

			err := writer.WriteBytes([]byte("0123456789"))
			a.Error(err)
			a.Len(sc.wrote, tc.writable)
			if !tc.fatal {
				a.True(isTimeout(err))
				a.NotErrorIs(err, ErrConnClosed)
				a.False(sc.closed)

				sc.writable = 4
				a.NoError(writer.WriteBytes([]byte("ok")))
				a.Equal([]byte{0, 2, 'o', 'k'}, sc.wrote)
				return
			}
			a.ErrorIs(err, ErrConnClosed)
			a.False(isTimeout(err))
			a.True(sc.closed)
			a.ErrorIs(writer.WriteBytes([]byte("ok")), ErrConnClosed)
		})
	}
}

func TestReceivePayload_TimeoutMidFrameIsConnClosed(t *testing.T) {
	a := require.New(t)
	sc := &scriptedConn{chunks: [][]byte{{0, 64, 1, 2, 3}}}
	tr := newTransport(newConn(sc), nil, "test-session", nil, nil)

	_, _, err := tr.ReceivePayload()
	a.ErrorIs(err, ErrConnClosed)
	a.NotErrorIs(err, ErrReceiveTimeout)
}
