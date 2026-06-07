package handlers

import (
	"encoding/binary"
	"io"
	"net"
	"time"
)

type rawTCPAdapter struct {
	conn    net.Conn
	maxSize int
}

func (t *rawTCPAdapter) ReadBytes() ([]byte, error) {
	var length uint16
	if err := binary.Read(t.conn, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	if t.maxSize > 0 && int(length) > t.maxSize {
		return nil, io.ErrUnexpectedEOF
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(t.conn, data); err != nil {
		return nil, err
	}
	return data, nil
}

func (t *rawTCPAdapter) WriteBytes(data []byte) error {
	if err := binary.Write(t.conn, binary.BigEndian, uint16(len(data))); err != nil {
		return err
	}
	_, err := t.conn.Write(data)
	return err
}

func (t *rawTCPAdapter) Close() error {
	return t.conn.Close()
}

func (t *rawTCPAdapter) SetDeadline(deadline time.Time) error {
	return t.conn.SetDeadline(deadline)
}
