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

type Conn struct {
	conn          net.Conn
	connType      connType
	isClosed      bool
	readDeadline  time.Duration
	writeDeadline time.Duration
}

func (c *Conn) Close() error {
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

func (c *Conn) Read(buf []byte) (int, error) {
	if err := c.checkAndSetDeadline(c.readDeadline); err != nil {
		return 0, err
	}

	// TODO(h.yazdani): Since the connection is being reused, even in case of an
	//  error it must be fully read (and discarded).

	n, err := c.conn.Read(buf)
	switch {
	default:
		return n, nil
	case err != nil:
		return 0, fmt.Errorf("reading full: %w", err)
	}
}

func (c *Conn) ReadBytes() ([]byte, error) {
	l, err := c.readLen()
	if err != nil {
		return nil, fmt.Errorf("message length: %w", err)
	}
	buf := make([]byte, l)
	_, err = c.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("reading message: %w", err)
	}
	return buf, nil
}

func (c *Conn) Write(data []byte) (int, error) {
	if err := c.checkAndSetDeadline(c.writeDeadline); err != nil {
		return 0, err
	}

	n, err := c.conn.Write(data)
	if err != nil {
		return 0, fmt.Errorf("writing message: %w", err)
	}
	return n, nil
}

func (c *Conn) WriteBytes(data []byte) error {
	_, err := c.writeLen(data)
	if err != nil {
		return fmt.Errorf("writing length: %w", err)
	}
	_, err = c.Write(data)
	if err != nil {
		return fmt.Errorf("writing message: %w", err)
	}
	return nil
}

func (c *Conn) readLen() (int, error) {
	if err := c.checkAndSetDeadline(c.readDeadline); err != nil {
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

func (c *Conn) writeLen(data []byte) (int, error) {
	if err := c.checkAndSetDeadline(c.writeDeadline); err != nil {
		return 0, err
	}

	msgLen := len(data)
	if len(data) > maxTransportSize {
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
		return n, nil
	}
}

func (c *Conn) checkAndSetDeadline(deadline time.Duration) error {
	if c.isClosed {
		return ErrConnClosed
	}
	err := c.SetReadDeadline(time.Now().Add(deadline))
	if err != nil {
		return fmt.Errorf("setting read deadline: %w", err)
	}
	return nil
}

func (c *Conn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

type ConnOption func(*Conn) error

func ConnWithReadTimeout(timeout time.Duration) ConnOption {
	return func(conn *Conn) error {
		conn.readDeadline = timeout
		return nil
	}
}

func ConnWithWriteTimeout(timeout time.Duration) ConnOption {
	return func(conn *Conn) error {
		conn.writeDeadline = timeout
		return nil
	}
}

func newConn(c net.Conn, opts ...ConnOption) (*Conn, error) {
	conn := &Conn{
		conn:          c,
		connType:      tcp,
		isClosed:      false,
		writeDeadline: 1 * time.Minute,
		readDeadline:  10 * time.Minute,
	}

	for _, opt := range opts {
		if err := opt(conn); err != nil {
			return nil, err
		}
	}

	return conn, nil
}
