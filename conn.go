package kamune

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"
)

type connType int

const (
	invalidConn connType = iota
	tcp
	udp
)

type Conn interface {
	net.Conn
	ReadBytes() ([]byte, error)
	WriteBytes(data []byte) error
}

type conn struct {
	conn     net.Conn
	connType connType

	// closed is accessed concurrently by read/write/close paths.
	closed uint32

	readDeadline  time.Duration
	writeDeadline time.Duration
}

func (c *conn) Close() error {
	if !atomic.CompareAndSwapUint32(&c.closed, 0, 1) {
		return ErrConnClosed
	}
	if err := c.conn.Close(); err != nil {
		// Roll back the closed flag if close fails, so callers can retry/inspect.
		atomic.StoreUint32(&c.closed, 0)
		return err
	}
	return nil
}

// TODO(h.yazdani): support chunked read and writes

func (c *conn) Read(buf []byte) (int, error) {
	if err := c.checkReadDeadline(c.readDeadline); err != nil {
		return 0, err
	}

	// TODO(h.yazdani): Since the connection is being reused, even in case of an
	//  error it must be fully read (and discarded).

	n, err := c.conn.Read(buf)
	if err != nil {
		return 0, fmt.Errorf("reading from conn: %w", err)
	}
	return n, nil
}

func (c *conn) ReadBytes() ([]byte, error) {
	l, err := c.readLen()
	if err != nil {
		return nil, fmt.Errorf("message length: %w", err)
	}

	buf := make([]byte, l)
	if _, err := io.ReadFull(c.conn, buf); err != nil {
		return nil, fmt.Errorf("reading message: %w", err)
	}
	return buf, nil
}

func (c *conn) Write(data []byte) (int, error) {
	if err := c.checkWriteDeadline(c.writeDeadline); err != nil {
		return 0, err
	}

	n, err := c.conn.Write(data)
	if err != nil {
		return 0, fmt.Errorf("writing message: %w", err)
	}
	return n, nil
}

func (c *conn) WriteBytes(data []byte) error {
	_, err := c.writeLen(data)
	if err != nil {
		return fmt.Errorf("writing length: %w", err)
	}

	if err := c.checkWriteDeadline(c.writeDeadline); err != nil {
		return err
	}

	// Ensure the full payload is written.
	written := 0
	for written < len(data) {
		n, err := c.conn.Write(data[written:])
		if err != nil {
			return fmt.Errorf("writing message: %w", err)
		}
		if n == 0 {
			return fmt.Errorf("writing message: wrote 0 bytes")
		}
		written += n
	}
	return nil
}

func (c *conn) readLen() (int, error) {
	if err := c.checkReadDeadline(c.readDeadline); err != nil {
		return 0, err
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(c.conn, lenBuf[:]); err != nil {
		return 0, fmt.Errorf("reading: %w", err)
	}

	msgLen := binary.BigEndian.Uint16(lenBuf[:])
	if msgLen > maxTransportSize {
		return 0, ErrMessageTooLarge
	}

	return int(msgLen), nil
}

func (c *conn) writeLen(data []byte) (int, error) {
	if err := c.checkWriteDeadline(c.writeDeadline); err != nil {
		return 0, err
	}

	msgLen := len(data)
	if msgLen > maxTransportSize {
		return 0, ErrMessageTooLarge
	}

	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(msgLen))

	// Ensure the full length prefix is written.
	written := 0
	for written < len(lenBuf) {
		n, err := c.conn.Write(lenBuf[written:])
		if err != nil {
			return 0, fmt.Errorf("writing length: %w", err)
		}
		if n == 0 {
			return 0, fmt.Errorf("writing length: wrote 0 bytes")
		}
		written += n
	}

	return msgLen, nil
}

func (c *conn) checkReadDeadline(deadline time.Duration) error {
	if atomic.LoadUint32(&c.closed) != 0 {
		return ErrConnClosed
	}

	// A non-positive deadline disables timeouts (no deadline).
	// This makes ConnWithReadTimeout(0) a safe way to disable deadlines.
	if deadline <= 0 {
		if err := c.SetReadDeadline(time.Time{}); err != nil {
			return fmt.Errorf("clearing read deadline: %w", err)
		}
		return nil
	}

	if err := c.SetReadDeadline(time.Now().Add(deadline)); err != nil {
		return fmt.Errorf("setting read deadline: %w", err)
	}
	return nil
}

func (c *conn) checkWriteDeadline(deadline time.Duration) error {
	if atomic.LoadUint32(&c.closed) != 0 {
		return ErrConnClosed
	}

	// A non-positive deadline disables timeouts (no deadline).
	// This makes ConnWithWriteTimeout(0) a safe way to disable deadlines.
	if deadline <= 0 {
		if err := c.SetWriteDeadline(time.Time{}); err != nil {
			return fmt.Errorf("clearing write deadline: %w", err)
		}
		return nil
	}

	if err := c.SetWriteDeadline(time.Now().Add(deadline)); err != nil {
		return fmt.Errorf("setting write deadline: %w", err)
	}
	return nil
}

func (c *conn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *conn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *conn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *conn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *conn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

type ConnOption func(*conn) error

func ConnWithReadTimeout(timeout time.Duration) ConnOption {
	return func(conn *conn) error {
		conn.readDeadline = timeout
		return nil
	}
}

func ConnWithWriteTimeout(timeout time.Duration) ConnOption {
	return func(conn *conn) error {
		conn.writeDeadline = timeout
		return nil
	}
}

func newConn(c net.Conn, opts ...ConnOption) (*conn, error) {
	cn := &conn{
		conn:          c,
		connType:      tcp,
		closed:        0,
		writeDeadline: 1 * time.Minute,
		readDeadline:  5 * time.Minute,
	}

	for _, opt := range opts {
		if err := opt(cn); err != nil {
			return nil, err
		}
	}

	return cn, nil
}
