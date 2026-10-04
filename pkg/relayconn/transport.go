package relayconn

import (
	"context"
	"crypto/tls"
	"errors"
	"math"
	"net"
	"os"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/kamune-org/kamune/pkg/exchange"
)

// DefaultMaxFrameSize is the default upper bound on a single frame
// the client will accept. It matches the relay server's default
// max_message_size and protects the client from a malicious or
// buggy relay that would otherwise force large allocations.
const DefaultMaxFrameSize = 65536

// wsReadLimit is the largest WebSocket message the client accepts from
// the relay. coder/websocket defaults to 32 KiB, which is below the
// relay's default max_message_size (65536) and below padded kamune
// frames once the relay leg has wrapped them. Twice DefaultMaxFrameSize
// leaves room for relays configured with a larger max_message_size and
// still bounds each message.
const wsReadLimit = 2 * DefaultMaxFrameSize

// dialWS opens a client WebSocket to the relay and raises its read
// limit to wsReadLimit. Every client WebSocket must be opened through
// it.
func dialWS(
	ctx context.Context, url string, opts *websocket.DialOptions,
) (*websocket.Conn, error) {
	ws, _, err := websocket.Dial(ctx, url, opts)
	if err != nil {
		return nil, err
	}
	ws.SetReadLimit(wsReadLimit)
	return ws, nil
}

// The relay transports report their frame limit, so an exchange.Channel
// rejects a frame they cannot carry before sealing it.
var (
	_ exchange.FrameLimiter = (*tcpAdapter)(nil)
	_ exchange.FrameLimiter = (*tlsAdapter)(nil)
	_ exchange.FrameLimiter = (*wsAdapter)(nil)
	_ exchange.FrameLimiter = (*RelayConn)(nil)
)

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
func (a *tcpAdapter) MaxFrameSize() int          { return a.f.MaxFrameSize() }
func (a *tcpAdapter) SetDeadline(t time.Time) error {
	return a.f.SetDeadline(t)
}
func (a *tcpAdapter) SetWriteDeadline(t time.Time) error {
	return a.f.SetWriteDeadline(t)
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
func (a *tlsAdapter) MaxFrameSize() int          { return a.f.MaxFrameSize() }
func (a *tlsAdapter) SetDeadline(t time.Time) error {
	return a.f.SetDeadline(t)
}
func (a *tlsAdapter) SetWriteDeadline(t time.Time) error {
	return a.f.SetWriteDeadline(t)
}

// wsAdapter wraps a WebSocket connection as an exchange.ReadWriter.
// Every read and write runs under ctx; cancelling it ends them and
// closes the WebSocket.
type wsAdapter struct {
	writeDeadline time.Time
	ctx           context.Context
	conn          *websocket.Conn
	cancel        context.CancelFunc
	deadlineMu    sync.Mutex
}

// newWSAdapter wraps the client WebSocket ws. Its context keeps the
// values of ctx but not its cancellation or deadline: the caller's
// context bounds only the relay handshake, and the connection then
// lasts until Close.
func newWSAdapter(ctx context.Context, ws *websocket.Conn) *wsAdapter {
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	return &wsAdapter{conn: ws, ctx: ctx, cancel: cancel}
}

// abort ends a relay handshake that did not complete. Cancelling the
// context first makes a blocked read close the WebSocket at once
// rather than leaving Close to wait out the close handshake.
func (w *wsAdapter) abort() {
	w.cancel()
	_ = w.conn.Close(websocket.StatusNormalClosure, "exchange failed")
}

func (w *wsAdapter) ReadBytes() ([]byte, error) {
	_, data, err := w.conn.Read(w.ctx)
	return data, err
}

func (w *wsAdapter) WriteBytes(data []byte) error {
	w.deadlineMu.Lock()
	deadline := w.writeDeadline
	w.deadlineMu.Unlock()

	ctx := w.ctx
	if !deadline.IsZero() {
		if !deadline.After(time.Now()) {
			return os.ErrDeadlineExceeded
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}
	err := w.conn.Write(ctx, websocket.MessageBinary, data)
	if errors.Is(err, context.DeadlineExceeded) {
		return os.ErrDeadlineExceeded
	}
	return err
}

// MaxFrameSize reports the largest frame WriteBytes accepts. A WebSocket
// message has no 16-bit bound of its own, but the relay may forward the
// frame to a peer on a TCP or TLS leg, which carries at most
// math.MaxUint16 bytes, so every relay transport reports the same limit.
func (w *wsAdapter) MaxFrameSize() int { return math.MaxUint16 }

func (w *wsAdapter) Close() error {
	err := w.conn.Close(websocket.StatusNormalClosure, "closed")
	if w.cancel != nil {
		w.cancel()
	}
	return err
}

func (w *wsAdapter) SetDeadline(t time.Time) error {
	return w.SetWriteDeadline(t)
}

func (w *wsAdapter) SetWriteDeadline(t time.Time) error {
	w.deadlineMu.Lock()
	w.writeDeadline = t
	w.deadlineMu.Unlock()
	return nil
}
