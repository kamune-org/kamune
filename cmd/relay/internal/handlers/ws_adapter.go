package handlers

import (
	"context"
	"time"

	"github.com/coder/websocket"
)

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
