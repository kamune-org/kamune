package kamune

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/kamune-org/kamune/pkg/exchange"
)

type Conn interface {
	exchange.ReadWriter
	SetDeadline(t time.Time) error
	Close() error
}

// conn implements [Conn] interface, providing frame-based read and write
// operations over a network connection.
//
// It also implements [net.Conn] interface.
type conn struct {
	currentReadDeadline  time.Time
	currentWriteDeadline time.Time
	conn                 net.Conn
	readDeadline         time.Duration
	writeDeadline        time.Duration
	mu                   sync.Mutex
	closed               bool
}

func (c *conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrConnClosed
	}
	if err := c.conn.Close(); err != nil {
		return err
	}
	c.closed = true
	return nil
}

// TODO(h.yazdani): support chunked read and writes

func (c *conn) Read(buf []byte) (int, error) {
	if err := c.checkReadDeadline(c.readDeadline); err != nil {
		return 0, err
	}

	// TODO(h.yazdani): Since the connection is being reused, even in case of an
	// error, it must be fully read (and discarded).

	n, err := c.conn.Read(buf)
	if err != nil {
		return 0, fmt.Errorf("reading from conn: %w", err)
	}
	return n, nil
}

func (c *conn) ReadBytes() ([]byte, error) {
	l, err := c.readLen()
	if err != nil {
		return nil, fmt.Errorf("get message length: %w", err)
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
			return fmt.Errorf(
				"wrote %d bytes instead of %d", written, len(data),
			)
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
		return 0, fmt.Errorf("reading first two bytes: %w", err)
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

	if len(data) > int(maxTransportSize) {
		return 0, ErrMessageTooLarge
	}
	msgLen := uint16(len(data))

	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], msgLen)

	// Ensure the full length prefix is written.
	written := 0
	for written < len(lenBuf) {
		n, err := c.conn.Write(lenBuf[written:])
		if err != nil {
			return 0, fmt.Errorf("writing length: %w", err)
		}
		if n == 0 {
			return 0, fmt.Errorf(
				"wrote %d bytes instead of %d", written, len(data),
			)
		}
		written += n
	}

	return int(msgLen), nil
}

func (c *conn) checkReadDeadline(deadline time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrConnClosed
	}

	// A non-positive deadline disables timeouts (no deadline).
	// This makes ConnWithReadTimeout(0) a safe way to disable deadlines.
	if deadline <= 0 {
		if err := c.conn.SetReadDeadline(time.Time{}); err != nil {
			return fmt.Errorf("clearing read deadline: %w", err)
		}
		c.currentReadDeadline = time.Time{}
		return nil
	}

	newDeadline := time.Now().Add(deadline)
	// Respect an existing shorter deadline (e.g. set by Ping).
	if !c.currentReadDeadline.IsZero() && c.currentReadDeadline.Before(newDeadline) {
		return nil
	}
	if err := c.conn.SetReadDeadline(newDeadline); err != nil {
		return fmt.Errorf("setting read deadline: %w", err)
	}
	c.currentReadDeadline = newDeadline
	return nil
}

func (c *conn) checkWriteDeadline(deadline time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrConnClosed
	}

	// A non-positive deadline disables timeouts (no deadline).
	// This makes ConnWithWriteTimeout(0) a safe way to disable deadlines.
	if deadline <= 0 {
		if err := c.conn.SetWriteDeadline(time.Time{}); err != nil {
			return fmt.Errorf("clearing write deadline: %w", err)
		}
		c.currentWriteDeadline = time.Time{}
		return nil
	}

	newDeadline := time.Now().Add(deadline)
	// Respect an existing shorter deadline.
	if !c.currentWriteDeadline.IsZero() && c.currentWriteDeadline.Before(newDeadline) {
		return nil
	}
	if err := c.conn.SetWriteDeadline(newDeadline); err != nil {
		return fmt.Errorf("setting write deadline: %w", err)
	}
	c.currentWriteDeadline = newDeadline
	return nil
}

func (c *conn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *conn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

func (c *conn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.currentReadDeadline = t
	c.currentWriteDeadline = t
	c.mu.Unlock()
	return c.conn.SetDeadline(t)
}

func (c *conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.currentReadDeadline = t
	c.mu.Unlock()
	return c.conn.SetReadDeadline(t)
}

func (c *conn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.currentWriteDeadline = t
	c.mu.Unlock()
	return c.conn.SetWriteDeadline(t)
}

func newConn(c net.Conn, opts ...ConnOption) *conn {
	cn := &conn{
		conn:          c,
		writeDeadline: 1 * time.Minute,
		readDeadline:  5 * time.Minute,
	}

	for _, opt := range opts {
		opt(cn)
	}

	return cn
}

type ConnOption func(*conn)

func ConnWithReadTimeout(timeout time.Duration) ConnOption {
	return func(conn *conn) { conn.readDeadline = timeout }
}

func ConnWithWriteTimeout(timeout time.Duration) ConnOption {
	return func(conn *conn) { conn.writeDeadline = timeout }
}
