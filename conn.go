package kamune

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

type ConnType int

const (
	TCP ConnType = iota
	UDP
)

type Conn struct {
	conn          net.Conn
	reader        *bufio.Reader
	connType      ConnType
	isClosed      bool
	readDeadline  time.Duration
	writeDeadline time.Duration
}

type ConnOption func(*Conn) error

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

func (c *Conn) Read() ([]byte, error) {
	err := c.conn.SetReadDeadline(time.Now().Add(c.readDeadline))
	if err != nil {
		return nil, fmt.Errorf("setting read deadline: %w", err)
	}
	if c.isClosed {
		return nil, ErrConnClosed
	}

	// TODO(h.yazdani): Since the connection is being reused, even in case of an
	//  error it must be fully read (and discarded).

	var lenBuf [2]byte
	if _, err := io.ReadFull(c.reader, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("reading length: %w", err)
	}
	msgLen := binary.BigEndian.Uint16(lenBuf[:])
	if msgLen > maxTransportSize {
		return nil, ErrMessageTooLarge
	}

	buf := make([]byte, msgLen)
	var n int
	if n, err = io.ReadFull(c.reader, buf[:]); err != nil {
		return nil, fmt.Errorf("reading length: %w", err)
	}
	switch {
	case n != int(msgLen):
		return nil, fmt.Errorf("expected %d bytes, read %d", msgLen, n)
	default:
		return buf, nil
	}
}

func (c *Conn) Write(data []byte) error {
	err := c.conn.SetWriteDeadline(time.Now().Add(c.writeDeadline))
	if err != nil {
		return fmt.Errorf("setting write deadline: %w", err)
	}
	if c.isClosed {
		return ErrConnClosed
	}

	msgLen := len(data)
	if len(data) > maxTransportSize {
		return ErrMessageTooLarge
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(msgLen))
	if _, err := c.conn.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("writing length: %w", err)
	}

	if _, err = c.conn.Write(data); err != nil {
		return fmt.Errorf("writing message: %w", err)
	}
	return nil
}

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
		reader:        bufio.NewReader(c),
		connType:      TCP,
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
