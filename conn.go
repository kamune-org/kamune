package kamune

import (
	"crypto/hpke"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

type connType int

const (
	invalidConn connType = iota
	tcp
	udp
)

type Conn interface {
	ReadBytes() ([]byte, error)
	WriteBytes(data []byte) error
	SetDeadline(t time.Time) error
	Close() error
}

type conn struct {
	conn     net.Conn
	connType connType
	mu       sync.Mutex

	closed bool

	readDeadline  time.Duration
	writeDeadline time.Duration
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
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
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
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
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

type ConnOption func(*conn)

func ConnWithReadTimeout(timeout time.Duration) ConnOption {
	return func(conn *conn) { conn.readDeadline = timeout }
}

func ConnWithWriteTimeout(timeout time.Duration) ConnOption {
	return func(conn *conn) { conn.writeDeadline = timeout }
}

func newConn(c net.Conn, opts ...ConnOption) (*conn, error) {
	cn := &conn{
		conn:          c,
		connType:      tcp,
		closed:        false,
		writeDeadline: 1 * time.Minute,
		readDeadline:  5 * time.Minute,
	}

	for _, opt := range opts {
		opt(cn)
	}

	return cn, nil
}

// encryptedConn uses HPKE to provide an encrypted communication. It is meant
// to be used during the handshake process and it should not be used for other
// purposes.
//
// It implements the [Conn] interface.
type encryptedConn struct {
	conn      Conn
	sender    *hpke.Sender
	recipient *hpke.Recipient
}

func newEncryptedConn(
	conn Conn, sender *hpke.Sender, recipient *hpke.Recipient,
) *encryptedConn {
	return &encryptedConn{
		conn:      conn,
		sender:    sender,
		recipient: recipient,
	}
}

func (ec *encryptedConn) ReadBytes() ([]byte, error) {
	encrypted, err := ec.conn.ReadBytes()
	if err != nil {
		return nil, fmt.Errorf("read encrypted: %w", err)
	}
	data, err := ec.recipient.Open(nil, encrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	return data, nil
}

func (ec *encryptedConn) WriteBytes(data []byte) error {
	encrypted, err := ec.sender.Seal(nil, data)
	if err != nil {
		return fmt.Errorf("encrypting: %w", err)
	}
	if err = ec.conn.WriteBytes(encrypted); err != nil {
		return fmt.Errorf("write encrypted: %w", err)
	}

	return nil
}

func (ec *encryptedConn) Close() error {
	return ec.conn.Close()
}

func (ec *encryptedConn) SetDeadline(t time.Time) error {
	return ec.conn.SetDeadline(t)
}
