package kamune

import (
	"encoding/binary"
	"fmt"
	"net"
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
	conn          net.Conn
	connType      connType
	isClosed      bool
	readDeadline  time.Duration
	writeDeadline time.Duration
}

func (c *conn) Close() error {
	if c.isClosed {
		return ErrConnClosed
	}
	err := c.conn.Close()
	if err != nil {
		return err
	}
	c.isClosed = true

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
	switch n, err := c.Read(buf); {
	case err != nil:
		return nil, fmt.Errorf("reading message: %w", err)
	case n != l:
		return nil, fmt.Errorf("read %d instead of %d", n, l)
	default:
		return buf, nil
	}
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
	l, err := c.writeLen(data)
	if err != nil {
		return fmt.Errorf("writing length: %w", err)
	}
	switch n, err := c.Write(data); {
	case err != nil:
		return fmt.Errorf("writing message: %w", err)
	case n != l:
		return fmt.Errorf("wrote %d instead of %d", n, l)
	default:
		return nil
	}
}

func (c *conn) readLen() (int, error) {
	if err := c.checkReadDeadline(c.readDeadline); err != nil {
		return 0, err
	}

	lenBuf := make([]byte, 2)
	n, err := c.conn.Read(lenBuf)
	switch {
	case err != nil:
		return 0, fmt.Errorf("reading: %w", err)
	case n != 2:
		return 0, fmt.Errorf("expected 2 bytes, got %d", n)
	}
	msgLen := binary.BigEndian.Uint16(lenBuf)
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
	switch n, err := c.conn.Write(lenBuf[:]); {
	case err != nil:
		return 0, fmt.Errorf("writing length: %w", err)
	case n != 2:
		return 0, fmt.Errorf("expected to write 2 bytes, wrote %d", n)
	default:
		return msgLen, nil
	}
}

func (c *conn) checkReadDeadline(deadline time.Duration) error {
	if c.isClosed {
		return ErrConnClosed
	}
	err := c.SetReadDeadline(time.Now().Add(deadline))
	if err != nil {
		return fmt.Errorf("setting read deadline: %w", err)
	}
	return nil
}

func (c *conn) checkWriteDeadline(deadline time.Duration) error {
	if c.isClosed {
		return ErrConnClosed
	}
	err := c.SetWriteDeadline(time.Now().Add(deadline))
	if err != nil {
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
		isClosed:      false,
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
