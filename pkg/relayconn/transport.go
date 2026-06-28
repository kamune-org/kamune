package relayconn

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/coder/websocket"
)

// DefaultMaxFrameSize is the default upper bound on a single frame
// the client will accept. It matches the relay server's default
// max_message_size and protects the client from a malicious or
// buggy relay that would otherwise force large allocations.
const DefaultMaxFrameSize = 65536

// tcpAdapter wraps a net.Conn with the relay's length-prefixed framing.
type tcpAdapter struct {
	f *Framing
}

func newTCPAdapter(conn net.Conn) *tcpAdapter {
	return &tcpAdapter{f: NewFraming(conn, DefaultMaxFrameSize)}
}

func (a *tcpAdapter) ReadBytes() ([]byte, error) { return a.f.ReadBytes() }
func (a *tcpAdapter) WriteBytes(d []byte) error  { return a.f.WriteBytes(d) }
func (a *tcpAdapter) Close() error               { return a.f.Close() }
func (a *tcpAdapter) SetDeadline(t time.Time) error {
	return a.f.SetDeadline(t)
}

// tlsAdapter wraps a *tls.Conn with the relay's length-prefixed framing.
type tlsAdapter struct {
	f *Framing
}

func newTLSAdapter(conn *tls.Conn) *tlsAdapter {
	return &tlsAdapter{f: NewFraming(conn, DefaultMaxFrameSize)}
}

func (a *tlsAdapter) ReadBytes() ([]byte, error) { return a.f.ReadBytes() }
func (a *tlsAdapter) WriteBytes(d []byte) error  { return a.f.WriteBytes(d) }
func (a *tlsAdapter) Close() error               { return a.f.Close() }
func (a *tlsAdapter) SetDeadline(t time.Time) error {
	return a.f.SetDeadline(t)
}

// wsAdapter wraps a WebSocket connection as an exchange.ReadWriter.
// It carries a context so the listener's lifecycle (Stop/Close) can
// cancel in-flight reads and writes.
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
