package kamune

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

var (
	ErrAlreadyClosed   = errors.New("connection has already been closed")
	ErrTooLargeMessage = errors.New("message is too large")
)

type Conn struct {
	conn          net.Conn
	reader        *bufio.Reader
	isClosed      bool
	readDeadline  time.Duration
	writeDeadline time.Duration
}

func (c *Conn) Close() error {
	if c.isClosed {
		return ErrAlreadyClosed
	}
	err := c.conn.Close()
	if err != nil {
		return err
	}
	c.isClosed = true

	return nil
}

//TODO: support chunked read and writes

func (c *Conn) Read() ([]byte, error) {
	err := c.conn.SetReadDeadline(time.Now().Add(c.readDeadline))
	if err != nil {
		return nil, fmt.Errorf("setting read deadline: %w", err)
	}
	if c.isClosed {
		return nil, ErrAlreadyClosed
	}

	var lenBuf [4]byte
	if _, err := io.ReadFull(c.conn, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("reading length: %w", err)
	}
	msgLen := binary.BigEndian.Uint32(lenBuf[:])
	if msgLen > maxTransportSize {
		return nil, ErrTooLargeMessage
	}

	buf := make([]byte, msgLen)
	n, err := c.reader.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("reading message: %w", err)
	}
	return buf[:n], nil
}

func (c *Conn) Write(data []byte) error {
	err := c.conn.SetWriteDeadline(time.Now().Add(c.writeDeadline))
	if err != nil {
		return fmt.Errorf("setting write deadline: %w", err)
	}
	if c.isClosed {
		return ErrAlreadyClosed
	}

	msgLen := len(data)
	if len(data) > maxTransportSize {
		return ErrTooLargeMessage
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(msgLen))
	if _, err := c.conn.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("writing length: %w", err)
	}

	if _, err := c.conn.Write(data); err != nil {
		return fmt.Errorf("writing message: %w", err)
	}
	return nil
}

func newConn(c net.Conn) Conn {
	return Conn{
		conn:          c,
		reader:        bufio.NewReader(c),
		isClosed:      false,
		writeDeadline: 10 * time.Second,
		readDeadline:  30 * time.Second,
	}
}
