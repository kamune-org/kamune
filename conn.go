package kamune

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

type Conn interface {
	Read() ([]byte, error)
	Write([]byte) error
	Close() error
}

type ConnOption[
	T any,
	P interface {
		*T
		Conn
	},
] func(P) error

func TCPConnWithReadTimeout(timeout time.Duration) ConnOption[tcpConn, *tcpConn] {
	return func(conn *tcpConn) error {
		conn.readDeadline = timeout
		return nil
	}
}

func TCPConnWithWriteTimeout(timeout time.Duration) ConnOption[tcpConn, *tcpConn] {
	return func(conn *tcpConn) error {
		conn.writeDeadline = timeout
		return nil
	}
}

type tcpConn struct {
	conn          net.Conn
	reader        *bufio.Reader
	isClosed      bool
	readDeadline  time.Duration
	writeDeadline time.Duration
}

func (c *tcpConn) Close() error {
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

//TODO(h.yazdani): support chunked read and writes

func (c *tcpConn) Read() ([]byte, error) {
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
	if _, err := io.ReadFull(c.conn, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("reading length: %w", err)
	}
	msgLen := binary.BigEndian.Uint16(lenBuf[:])
	if msgLen > maxTransportSize {
		return nil, ErrMessageTooLarge
	}

	buf := make([]byte, msgLen)
	n, err := c.reader.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("reading message: %w", err)
	}
	return buf[:n], nil
}

func (c *tcpConn) Write(data []byte) error {
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

	if _, err := c.conn.Write(data); err != nil {
		return fmt.Errorf("writing message: %w", err)
	}
	return nil
}

func newTCPConn(
	c net.Conn, opts ...ConnOption[tcpConn, *tcpConn],
) (*tcpConn, error) {
	tc := &tcpConn{
		conn:          c,
		reader:        bufio.NewReader(c),
		isClosed:      false,
		writeDeadline: 10 * time.Second,
		readDeadline:  30 * time.Second,
	}

	for _, opt := range opts {
		if err := opt(tc); err != nil {
			return nil, err
		}
	}

	return tc, nil
}
