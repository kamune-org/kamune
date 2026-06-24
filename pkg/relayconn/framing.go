package relayconn

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

// Framing implements the length-prefixed wire format used by the TCP and TLS
// transports. The wire format is a 2-byte big-endian length followed by exactly
// that many bytes of payload.
//
// Framing is the single source of truth for that format so the two endpoints of
// a connection cannot drift.
//
// A zero-value Framing is not usable; construct via NewFraming. Framing
// satisfies the exchange.ReadWriter interface (without context — the underlying
// conn drives cancellation).
type Framing struct {
	rw      io.ReadWriteCloser
	maxSize int // 0 = no limit
}

// NewFraming returns a Framing that reads from and writes to rw,
// rejecting frames whose declared length exceeds maxSize bytes. A
// maxSize of 0 disables the size check.
func NewFraming(rw io.ReadWriteCloser, maxSize int) *Framing {
	return &Framing{rw: rw, maxSize: maxSize}
}

// ReadBytes reads one length-prefixed frame and returns its payload.
// It returns an error if the declared length exceeds maxSize, if the
// underlying conn errors, or if the frame is truncated.
func (f *Framing) ReadBytes() ([]byte, error) {
	var length uint16
	if err := binary.Read(f.rw, binary.BigEndian, &length); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}
	if f.maxSize > 0 && int(length) > f.maxSize {
		return nil, fmt.Errorf("frame size %d exceeds max %d", length, f.maxSize)
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(f.rw, data); err != nil {
		return nil, fmt.Errorf("read data: %w", err)
	}
	return data, nil
}

// WriteBytes writes one length-prefixed frame.
func (f *Framing) WriteBytes(data []byte) error {
	if err := binary.Write(f.rw, binary.BigEndian, uint16(len(data))); err != nil {
		return fmt.Errorf("write length: %w", err)
	}
	if _, err := f.rw.Write(data); err != nil {
		return fmt.Errorf("write data: %w", err)
	}
	return nil
}

// Close closes the underlying ReadWriteCloser.
func (f *Framing) Close() error {
	return f.rw.Close()
}

// SetDeadline forwards to the underlying conn if it implements the
// deadline interface; otherwise it is a no-op (matching the behavior
// of exchange.Channel.SetDeadline).
func (f *Framing) SetDeadline(t time.Time) error {
	if d, ok := f.rw.(interface{ SetDeadline(time.Time) error }); ok {
		return d.SetDeadline(t)
	}
	return nil
}
