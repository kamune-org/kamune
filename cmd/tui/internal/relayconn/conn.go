package relayconn

import (
	"context"
	"encoding/base64"
	"os"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/kamune-org/kamune"
)

type relayMessage struct {
	Type      string `json:"type"`
	Sender    string `json:"sender,omitempty"`
	Receiver  string `json:"receiver,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	Data      string `json:"data,omitempty"`
}

// RelayConn implements [kamune.Conn] over a relay WebSocket. The synthetic
// session ID derived from both peers' keys is used for the entire session.
type RelayConn struct {
	ws        *websocket.Conn
	peerKey   []byte
	sessionID string

	buf   [][]byte
	bufMu sync.Mutex
	recv  chan struct{}

	ctx    context.Context
	cancel context.CancelFunc

	writeMu sync.Mutex

	deadline   time.Time
	deadlineMu sync.Mutex
}

func newRelayConn(
	ctx context.Context,
	ws *websocket.Conn,
	peerKey []byte,
	sessionID string,
) *RelayConn {
	ctx, cancel := context.WithCancel(ctx)
	return &RelayConn{
		ws:        ws,
		peerKey:   peerKey,
		sessionID: sessionID,
		recv:      make(chan struct{}, 1),
		ctx:       ctx,
		cancel:    cancel,
	}
}

func (rc *RelayConn) ReadBytes() ([]byte, error) {
	for {
		rc.bufMu.Lock()
		if len(rc.buf) > 0 {
			data := rc.buf[0]
			rc.buf = rc.buf[1:]
			rc.bufMu.Unlock()
			return data, nil
		}
		rc.bufMu.Unlock()

		rc.deadlineMu.Lock()
		dl := rc.deadline
		rc.deadlineMu.Unlock()

		var timer *time.Timer
		var timeout <-chan time.Time
		if !dl.IsZero() {
			dur := time.Until(dl)
			if dur <= 0 {
				return nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(dur)
			timeout = timer.C
		}

		select {
		case <-rc.recv:
			if timer != nil {
				timer.Stop()
			}
		case <-timeout:
			return nil, os.ErrDeadlineExceeded
		case <-rc.ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return nil, kamune.ErrConnClosed
		}
	}
}

func (rc *RelayConn) WriteBytes(data []byte) error {
	msg := relayMessage{
		Type:      "message",
		Receiver:  base64.RawURLEncoding.EncodeToString(rc.peerKey),
		SessionID: rc.sessionID,
		Data:      base64.RawURLEncoding.EncodeToString(data),
	}

	rc.writeMu.Lock()
	defer rc.writeMu.Unlock()
	return wsjson.Write(rc.ctx, rc.ws, msg)
}

func (rc *RelayConn) SetDeadline(t time.Time) error {
	rc.deadlineMu.Lock()
	rc.deadline = t
	rc.deadlineMu.Unlock()
	return nil
}

func (rc *RelayConn) Close() error {
	rc.cancel()
	return rc.ws.Close(websocket.StatusNormalClosure, "session closed")
}

func (rc *RelayConn) pushData(data []byte) {
	rc.bufMu.Lock()
	rc.buf = append(rc.buf, data)
	rc.bufMu.Unlock()
	select {
	case rc.recv <- struct{}{}:
	default:
	}
}
