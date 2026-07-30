package kamune

import (
	"bytes"
	"errors"
	"math"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var (
	_ net.Conn = new(conn)
	_ Conn     = new(conn)
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
