package relayleg

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// nonceLen is the XChaCha20-Poly1305 nonce size.
const nonceLen = chacha20poly1305.NonceSizeX

// recordOverhead is the XChaCha20-Poly1305 tag.
const recordOverhead = 16

// ReadWriter is a framed byte pipe. One ReadBytes or WriteBytes
// call is one frame.
type ReadWriter interface {
	ReadBytes() ([]byte, error)
	WriteBytes([]byte) error
}

// FrameLimiter is implemented by a ReadWriter whose WriteBytes
// rejects frames larger than MaxFrameSize bytes. A Channel checks
// the sealed size against it before encrypting, so a frame the
// ReadWriter cannot carry is rejected with ErrFrameTooLarge and
// does not break the Channel. A non-positive value means no limit.
type FrameLimiter interface {
	MaxFrameSize() int
}

// Channel is an ordered frame channel over a ReadWriter.
// Each direction has its own XChaCha20-Poly1305 key, IV and
// sequence number. Sequence numbers start at zero. The nonce is
// the IV XORed with 16 zero bytes followed by the big-endian
// sequence number. The AAD is empty.
//
// A frame the ReadWriter cannot carry is rejected with
// ErrFrameTooLarge before it is sealed, and the Channel stays
// usable. A write that fails after sealing, and a sequence number
// of 2^64-1, stick as ErrChannelBroken. A failed write also closes
// the ReadWriter when it implements io.Closer.
type Channel struct {
	conn     ReadWriter
	send     cipher.AEAD
	recv     cipher.AEAD
	writeErr error
	sendIV   [nonceLen]byte
	recvIV   [nonceLen]byte
	sendSeq  uint64
	recvSeq  uint64
	writeMu  sync.Mutex
}

var (
	_ ReadWriter   = (*Channel)(nil)
	_ FrameLimiter = (*Channel)(nil)
)

func newChannel(
	rw ReadWriter, keys *recordKeys, client bool,
) (*Channel, error) {
	defer keys.wipe()
	sendKey := keys.c2rKey
	recvKey := keys.r2cKey
	sendIV := keys.c2rIV
	recvIV := keys.r2cIV
	if !client {
		sendKey = keys.r2cKey
		recvKey = keys.c2rKey
		sendIV = keys.r2cIV
		recvIV = keys.c2rIV
	}
	send, err := chacha20poly1305.NewX(sendKey[:])
	if err != nil {
		return nil, fmt.Errorf("send aead: %w", err)
	}
	recv, err := chacha20poly1305.NewX(recvKey[:])
	if err != nil {
		return nil, fmt.Errorf("receive aead: %w", err)
	}
	clear(sendKey[:])
	clear(recvKey[:])
	if send.Overhead() != recordOverhead || send.NonceSize() != nonceLen {
		return nil, fmt.Errorf(
			"aead overhead %d nonce %d",
			send.Overhead(), send.NonceSize(),
		)
	}
	ch := &Channel{conn: rw, send: send, recv: recv}
	ch.sendIV = sendIV
	ch.recvIV = recvIV
	return ch, nil
}

// nonceAt writes iv XOR (16 zero bytes || uint64be(seq)).
func nonceAt(dst *[nonceLen]byte, iv [nonceLen]byte, seq uint64) {
	*dst = iv
	off := nonceLen - 8
	x := binary.BigEndian.Uint64(dst[off:]) ^ seq
	binary.BigEndian.PutUint64(dst[off:], x)
}

// ReadBytes opens the next record. An AEAD failure wraps
// ErrRecordAuth and does not advance the sequence number.
func (c *Channel) ReadBytes() ([]byte, error) {
	if c.recvSeq == math.MaxUint64 {
		return nil, fmt.Errorf(
			"%w: sequence exhausted", ErrChannelBroken,
		)
	}
	encrypted, err := c.conn.ReadBytes()
	if err != nil {
		return nil, fmt.Errorf("read record: %w", err)
	}
	var n [nonceLen]byte
	nonceAt(&n, c.recvIV, c.recvSeq)
	plain, err := c.recv.Open(nil, n[:], encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRecordAuth, err)
	}
	c.recvSeq++
	return plain, nil
}

// WriteBytes writes one record.
func (c *Channel) WriteBytes(data []byte) error {
	return c.WriteBytesWithin(data, 0)
}

// WriteBytesWithin writes data while holding the write lock.
// A positive timeout arms the connection write deadline for that
// write only, and clears it before the lock is released, so a
// concurrent writer cannot cancel it.
//
// A frame larger than the ReadWriter's FrameLimiter allows is
// rejected with ErrFrameTooLarge before encryption. Any other
// write failure breaks the Channel.
func (c *Channel) WriteBytesWithin(
	data []byte, timeout time.Duration,
) error {
	c.writeMu.Lock()
	broke, err := c.writeLocked(data, timeout)
	c.writeMu.Unlock()
	if broke {
		// Close outside the lock. Closing can block on a
		// handshake, and writeErr already fails writers that
		// are waiting for the lock.
		_ = c.Close()
	}
	return err
}

// writeLocked seals and writes one frame. broke reports whether
// this call broke the Channel, in which case the caller closes it.
// The caller must hold c.writeMu.
func (c *Channel) writeLocked(
	data []byte, timeout time.Duration,
) (bool, error) {
	if c.writeErr != nil {
		return false, c.writeErr
	}
	if l, ok := c.conn.(FrameLimiter); ok {
		limit := l.MaxFrameSize()
		size := len(data) + recordOverhead
		if limit > 0 && size > limit {
			return false, fmt.Errorf(
				"%w: %d bytes, limit %d",
				ErrFrameTooLarge, size, limit,
			)
		}
	}
	if timeout > 0 {
		deadline := time.Now().Add(timeout)
		_ = c.SetWriteDeadline(deadline)
		defer func() { _ = c.SetWriteDeadline(time.Time{}) }()
	}
	if c.sendSeq == math.MaxUint64 {
		c.writeErr = fmt.Errorf(
			"%w: sequence exhausted", ErrChannelBroken,
		)
		return true, c.writeErr
	}
	var n [nonceLen]byte
	nonceAt(&n, c.sendIV, c.sendSeq)
	sealed := c.send.Seal(nil, n[:], data, nil)
	c.sendSeq++
	if err := c.conn.WriteBytes(sealed); err != nil {
		// The peer will expect the sequence number this frame
		// used, so no later frame can be opened.
		c.writeErr = fmt.Errorf("%w: %w", ErrChannelBroken, err)
		return true, fmt.Errorf("write encrypted: %w", c.writeErr)
	}
	return false, nil
}

// MaxFrameSize reports the largest frame WriteBytes accepts: the
// ReadWriter's FrameLimiter limit less the AEAD tag, and never
// less than 1. It reports 0 when the ReadWriter has no limit.
func (c *Channel) MaxFrameSize() int {
	l, ok := c.conn.(FrameLimiter)
	if !ok {
		return 0
	}
	limit := l.MaxFrameSize()
	if limit <= 0 {
		return 0
	}
	return max(limit-recordOverhead, 1)
}

// Close closes the ReadWriter when it implements io.Closer.
func (c *Channel) Close() error {
	if cl, ok := c.conn.(io.Closer); ok {
		return cl.Close()
	}
	return nil
}

// SetDeadline sets the deadline on the ReadWriter when it has
// SetDeadline.
func (c *Channel) SetDeadline(t time.Time) error {
	d, ok := c.conn.(interface{ SetDeadline(time.Time) error })
	if !ok {
		return nil
	}
	return d.SetDeadline(t)
}

// SetWriteDeadline sets the write deadline on the ReadWriter when
// it has SetWriteDeadline.
func (c *Channel) SetWriteDeadline(t time.Time) error {
	d, ok := c.conn.(interface{ SetWriteDeadline(time.Time) error })
	if !ok {
		return nil
	}
	return d.SetWriteDeadline(t)
}

// setSendSeq sets the next send sequence number.
// Tests use it to reach sequence exhaustion.
func (c *Channel) setSendSeq(n uint64) {
	c.writeMu.Lock()
	c.sendSeq = n
	c.writeMu.Unlock()
}
