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

// AcceptedMeta lets a Conn carry caller data through the handshake.
// The value is copied onto the Transport before the handler runs.
type AcceptedMeta interface {
	AcceptedMeta() any
}

// conn implements [Conn] interface, providing frame-based read and write
// operations over a network connection. It also implements [net.Conn]
// interface.
//
// Read and write paths are serialized independently: readMu and writeMu protect
// complete frames, while deadlineMu coordinates automatic and explicit
// deadlines. This keeps TCP full-duplex working, makes each frame atomic, and
// allows SetDeadline to interrupt blocked I/O.
type conn struct {
	currentReadDeadline   time.Time
	currentWriteDeadline  time.Time
	conn                  net.Conn
	readDeadline          time.Duration
	writeDeadline         time.Duration
	readMu                sync.Mutex
	writeMu               sync.Mutex
	deadlineMu            sync.Mutex
	closed                atomic.Bool
	readDeadlineExplicit  bool
	writeDeadlineExplicit bool
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

// ReadBytes reads one length-prefixed frame. A failure before any byte of
// the frame has arrived, such as a read deadline, leaves the stream intact
// and the caller may retry. A failure part-way through a frame closes the
// conn and returns an error wrapping ErrConnClosed: the consumed bytes cannot
// be put back, so a later read would start in the middle of the frame.
func (c *conn) ReadBytes() ([]byte, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	l, err := c.readLenLocked()
	if err != nil {
		return nil, fmt.Errorf("get message length: %w", err)
	}

	buf := make([]byte, l)
	if n, err := io.ReadFull(c.conn, buf); err != nil {
		return nil, c.abortFrame(
			fmt.Errorf("reading message (%d of %d bytes): %w", n, l, err),
		)
	}
	return buf, nil
}

// abortFrame closes the conn after a read or write failed part-way through a
// frame. The returned error wraps ErrConnClosed but not cause, so a deadline
// that fired mid-frame is not mistaken for a retryable timeout.
func (c *conn) abortFrame(cause error) error {
	_ = c.Close()
	return fmt.Errorf("%w: partial frame: %v", ErrConnClosed, cause)
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

// WriteBytes writes one length-prefixed frame. A failure before any byte of
// the frame has been written, such as a write deadline, leaves the stream
// intact and the caller may retry. A failure part-way through a frame closes
// the conn and returns an error wrapping ErrConnClosed: the peer already has
// part of the frame, so a retried frame would be read as the rest of it.
func (c *conn) WriteBytes(data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if err := c.checkWriteDeadlineLocked(c.writeDeadline); err != nil {
		return fmt.Errorf("writing length: %w", err)
	}
	if len(data) > math.MaxUint16 {
		return fmt.Errorf("writing length: %w", ErrMessageTooLarge)
	}

	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(data)))
	total := len(lenBuf) + len(data)
	sent := 0
	for _, part := range [][]byte{lenBuf[:], data} {
		for written := 0; written < len(part); {
			n, err := c.conn.Write(part[written:])
			written += n
			sent += n
			if err == nil && n == 0 {
				err = io.ErrShortWrite
			}
			if err == nil {
				continue
			}
			err = fmt.Errorf(
				"writing message (%d of %d bytes): %w", sent, total, err,
			)
			if sent > 0 {
				return c.abortFrame(err)
			}
			return err
		}
	}
	return nil
}

// MaxFrameSize reports the largest payload WriteBytes accepts, the bound of
// the 2-byte length prefix. It implements [exchange.FrameLimiter].
func (c *conn) MaxFrameSize() int { return math.MaxUint16 }

// readLenLocked reads the 2-byte length prefix. Caller must hold c.readMu.
func (c *conn) readLenLocked() (uint16, error) {
	if err := c.checkReadDeadlineLocked(c.readDeadline); err != nil {
		return 0, err
	}

	var lenBuf [2]byte
	if n, err := io.ReadFull(c.conn, lenBuf[:]); err != nil {
		err = fmt.Errorf("reading first two bytes: %w", err)
		if n > 0 {
			return 0, c.abortFrame(err)
		}
		return 0, err
	}

	return binary.BigEndian.Uint16(lenBuf[:]), nil
}

// checkReadDeadlineLocked refreshes the read deadline if needed.
// Caller must hold c.readMu.
func (c *conn) checkReadDeadlineLocked(deadline time.Duration) error {
	if c.closed.Load() {
		return ErrConnClosed
	}
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()

	if c.readDeadlineExplicit {
		return nil
	}

	// A non-positive deadline disables timeouts (no deadline).
	// This makes ConnWithReadTimeout(0) a safe way to disable deadlines.
	if deadline <= 0 {
		if c.currentReadDeadline.IsZero() {
			return nil
		}
		if err := c.conn.SetReadDeadline(time.Time{}); err != nil {
			return fmt.Errorf("clearing read deadline: %w", err)
		}
		c.currentReadDeadline = time.Time{}
		return nil
	}

	newDeadline := time.Now().Add(deadline)
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
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()

	if c.writeDeadlineExplicit {
		return nil
	}

	// A non-positive deadline disables timeouts (no deadline).
	// This makes ConnWithWriteTimeout(0) a safe way to disable deadlines.
	if deadline <= 0 {
		if c.currentWriteDeadline.IsZero() {
			return nil
		}
		if err := c.conn.SetWriteDeadline(time.Time{}); err != nil {
			return fmt.Errorf("clearing write deadline: %w", err)
		}
		c.currentWriteDeadline = time.Time{}
		return nil
	}

	newDeadline := time.Now().Add(deadline)
	if err := c.conn.SetWriteDeadline(newDeadline); err != nil {
		return fmt.Errorf("setting write deadline: %w", err)
	}
	c.currentWriteDeadline = newDeadline
	return nil
}

func (c *conn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *conn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

func (c *conn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()

	if err := c.conn.SetDeadline(t); err != nil {
		return err
	}
	c.currentReadDeadline = t
	c.currentWriteDeadline = t
	c.readDeadlineExplicit = !t.IsZero()
	c.writeDeadlineExplicit = !t.IsZero()
	return nil
}

func (c *conn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()

	if err := c.conn.SetReadDeadline(t); err != nil {
		return err
	}
	c.currentReadDeadline = t
	c.readDeadlineExplicit = !t.IsZero()
	return nil
}

func (c *conn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()

	if err := c.conn.SetWriteDeadline(t); err != nil {
		return err
	}
	c.currentWriteDeadline = t
	c.writeDeadlineExplicit = !t.IsZero()
	return nil
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
