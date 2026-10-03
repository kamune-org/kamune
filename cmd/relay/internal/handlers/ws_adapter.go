package handlers

import (
	"context"
	"sync"
	"time"

	"github.com/coder/websocket"
)

type wsAdapter struct {
	conn          *websocket.Conn
	mu            sync.Mutex
	writeDeadline time.Time
}

func (w *wsAdapter) ReadBytes() ([]byte, error) {
	_, data, err := w.conn.Read(context.Background())
	return data, err
}

func (w *wsAdapter) WriteBytes(data []byte) error {
	w.mu.Lock()
	dl := w.writeDeadline
	w.mu.Unlock()

	ctx := context.Background()
	if !dl.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, dl)
		defer cancel()
	}
	return w.conn.Write(ctx, websocket.MessageBinary, data)
}

func (w *wsAdapter) Close() error {
	return w.conn.Close(websocket.StatusNormalClosure, "closed")
}

func (w *wsAdapter) SetDeadline(t time.Time) error {
	return w.SetWriteDeadline(t)
}

func (w *wsAdapter) SetWriteDeadline(t time.Time) error {
	w.mu.Lock()
	w.writeDeadline = t
	w.mu.Unlock()
	return nil
}
