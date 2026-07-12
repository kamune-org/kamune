package kamune

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kamune-org/kamune/pkg/exchange"
)

// Conn is the abstract transport connection used by the kamune protocol. It
// extends exchange.ReadWriter with deadline and close operations.
type Conn interface {
	exchange.ReadWriter
	SetDeadline(t time.Time) error
	Close() error
}

// conn implements [Conn] interface, providing frame-based read and write
// operations over a network connection. It also implements [net.Conn]
// interface.
//
// Read and write paths are serialized independently: readMu protects the
// entire ReadBytes operation (length prefix + payload) and read deadlines;
// writeMu protects the entire WriteBytes operation and write deadlines.
// This keeps TCP full-duplex working while making each frame's two-step
// read/write atomic.
type conn struct {
	currentReadDeadline  time.Time
	currentWriteDeadline time.Time
	conn                 net.Conn
	readDeadline         time.Duration
	writeDeadline        time.Duration
	readMu               sync.Mutex
	writeMu              sync.Mutex
	closed               atomic.Bool
}

func (c *conn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return ErrConnClosed
	}
	return c.conn.Close()
}

// TODO(h.yazdani): support chunked read and writes

func (c *conn) Read(buf []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if err := c.checkReadDeadlineLocked(c.readDeadline); err != nil {
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
	c.readMu.Lock()
	defer c.readMu.Unlock()

	l, err := c.readLenLocked()
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
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if err := c.checkWriteDeadlineLocked(c.writeDeadline); err != nil {
		return 0, err
	}

	n, err := c.conn.Write(data)
	if err != nil {
		return 0, fmt.Errorf("writing message: %w", err)
	}
	return n, nil
}

func (c *conn) WriteBytes(data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	_, err := c.writeLenLocked(data)
	if err != nil {
		return fmt.Errorf("writing length: %w", err)
	}

	if err := c.checkWriteDeadlineLocked(c.writeDeadline); err != nil {
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

// readLenLocked reads the 2-byte length prefix. Caller must hold c.readMu.
func (c *conn) readLenLocked() (uint16, error) {
	if err := c.checkReadDeadlineLocked(c.readDeadline); err != nil {
		return 0, err
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(c.conn, lenBuf[:]); err != nil {
		return 0, fmt.Errorf("reading first two bytes: %w", err)
	}

	return binary.BigEndian.Uint16(lenBuf[:]), nil
}

// writeLenLocked writes the 2-byte length prefix. Caller must hold c.writeMu.
func (c *conn) writeLenLocked(data []byte) (int, error) {
	if err := c.checkWriteDeadlineLocked(c.writeDeadline); err != nil {
		return 0, err
	}

	if len(data) > math.MaxUint16 {
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

// checkReadDeadlineLocked refreshes the read deadline if needed.
// Caller must hold c.readMu.
func (c *conn) checkReadDeadlineLocked(deadline time.Duration) error {
	if c.closed.Load() {
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
	switch {
	case c.currentReadDeadline.IsZero():
		// No deadline set — apply the new one.
	case c.currentReadDeadline.Before(time.Now()):
		// Existing deadline expired — replace it.
	case c.currentReadDeadline.Before(newDeadline):
		// Existing deadline is tighter — keep it, skip the syscall.
		return nil
	}
	if err := c.conn.SetReadDeadline(newDeadline); err != nil {
		return fmt.Errorf("setting read deadline: %w", err)
	}
	c.currentReadDeadline = newDeadline
	return nil
}

// checkWriteDeadlineLocked refreshes the write deadline if needed.
// Caller must hold c.writeMu.
func (c *conn) checkWriteDeadlineLocked(deadline time.Duration) error {
	if c.closed.Load() {
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
	switch {
	case c.currentWriteDeadline.IsZero():
		// No deadline set — apply the new one.
	case c.currentWriteDeadline.Before(time.Now()):
		// Existing deadline expired — replace it.
	case c.currentWriteDeadline.Before(newDeadline):
		// Existing deadline is tighter — keep it, skip the syscall.
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
	c.readMu.Lock()
	c.currentReadDeadline = t
	c.readMu.Unlock()

	c.writeMu.Lock()
	c.currentWriteDeadline = t
	c.writeMu.Unlock()

	return c.conn.SetDeadline(t)
}

func (c *conn) SetReadDeadline(t time.Time) error {
	c.readMu.Lock()
	c.currentReadDeadline = t
	c.readMu.Unlock()
	return c.conn.SetReadDeadline(t)
}

func (c *conn) SetWriteDeadline(t time.Time) error {
	c.writeMu.Lock()
	c.currentWriteDeadline = t
	c.writeMu.Unlock()
	return c.conn.SetWriteDeadline(t)
}

// NewConn wraps a pre-established [net.Conn] in the kamune conn adapter and
// returns it as a [Conn]. Use with [DialWithFunc] when the dial step happens
// outside [NewDialer] (e.g. P2P hole-punched sockets).
func NewConn(c net.Conn, opts ...ConnOption) Conn {
	return newConn(c, opts...)
}

// newConn wraps a net.Conn with framing, deadlines, and functional options.
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
