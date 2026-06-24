package handlers

import (
	"net"
	"time"

	"github.com/kamune-org/kamune/pkg/relayconn"
)

// rawTCPAdapter wraps a net.Conn with the relay's length-prefixed wire
// format. It composes a relayconn.Framing that enforces the server's
// max_message_size so oversized frames are rejected before allocation.
type rawTCPAdapter struct {
	f *relayconn.Framing
}

func newRawTCPAdapter(conn net.Conn, maxSize int) *rawTCPAdapter {
	return &rawTCPAdapter{f: relayconn.NewFraming(conn, maxSize)}
}

func (a *rawTCPAdapter) ReadBytes() ([]byte, error) {
	return a.f.ReadBytes()
}

func (a *rawTCPAdapter) WriteBytes(data []byte) error {
	return a.f.WriteBytes(data)
}

func (a *rawTCPAdapter) Close() error {
	return a.f.Close()
}

func (a *rawTCPAdapter) SetDeadline(t time.Time) error {
	return a.f.SetDeadline(t)
}
