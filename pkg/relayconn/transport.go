package relayconn

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/coder/websocket"
)

// tcpAdapter wraps a net.Conn with length-prefixed framing (uint16 BE).
type tcpAdapter struct {
	conn net.Conn
}

func (t *tcpAdapter) ReadBytes() ([]byte, error) {
	var length uint16
	if err := binary.Read(t.conn, binary.BigEndian, &length); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(t.conn, data); err != nil {
		return nil, fmt.Errorf("read data: %w", err)
	}
	return data, nil
}

func (t *tcpAdapter) WriteBytes(data []byte) error {
	err := binary.Write(t.conn, binary.BigEndian, uint16(len(data)))
	if err != nil {
		return fmt.Errorf("write length: %w", err)
	}
	_, err = t.conn.Write(data)
	if err != nil {
		return fmt.Errorf("write data: %w", err)
	}
	return nil
}

func (t *tcpAdapter) Close() error {
	return t.conn.Close()
}

func (t *tcpAdapter) SetDeadline(deadline time.Time) error {
	return t.conn.SetDeadline(deadline)
}

// tlsAdapter wraps a tls.Conn with length-prefixed framing (uint16 BE).
type tlsAdapter struct {
	conn *tls.Conn
}

func (t *tlsAdapter) ReadBytes() ([]byte, error) {
	var length uint16
	if err := binary.Read(t.conn, binary.BigEndian, &length); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(t.conn, data); err != nil {
		return nil, fmt.Errorf("read data: %w", err)
	}
	return data, nil
}

func (t *tlsAdapter) WriteBytes(data []byte) error {
	err := binary.Write(t.conn, binary.BigEndian, uint16(len(data)))
	if err != nil {
		return fmt.Errorf("write length: %w", err)
	}
	_, err = t.conn.Write(data)
	if err != nil {
		return fmt.Errorf("write data: %w", err)
	}
	return nil
}

func (t *tlsAdapter) Close() error {
	return t.conn.Close()
}

func (t *tlsAdapter) SetDeadline(deadline time.Time) error {
	return t.conn.SetDeadline(deadline)
}

// wsAdapter wraps a WebSocket connection as an exchange.ReadWriter.
type wsAdapter struct {
	conn *websocket.Conn
	ctx  context.Context
}

func (w *wsAdapter) ReadBytes() ([]byte, error) {
	_, data, err := w.conn.Read(w.ctx)
	return data, err
}

func (w *wsAdapter) WriteBytes(data []byte) error {
	return w.conn.Write(w.ctx, websocket.MessageBinary, data)
}

func (w *wsAdapter) Close() error {
	return w.conn.Close(websocket.StatusNormalClosure, "closed")
}

func (w *wsAdapter) SetDeadline(time.Time) error { return nil }
