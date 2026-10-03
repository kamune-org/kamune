package exchange

import (
	"crypto/hpke"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"
)

// HPKE ciphersuite components used for key establishment.
// MLKEM768-X25519 provides hybrid post-quantum + classical security.
// HKDF-SHA512 is the KDF and ChaCha20Poly1305 is the AEAD used by HPKE to
// protect Introduction, Handshake, and Challenge messages. After the
// handshake, session encryption uses XChaCha20-Poly1305 via enigma.
var (
	hpkeKEM  = hpke.MLKEM768X25519
	hpkeKDF  = hpke.HKDFSHA512
	hpkeAEAD = hpke.ChaCha20Poly1305
)

// Overhead is the number of bytes a Channel adds to every frame it writes
// (the ChaCha20-Poly1305 tag).
const Overhead = 16

type ReadWriter interface {
	ReadBytes() ([]byte, error)
	WriteBytes([]byte) error
}

// FrameLimiter is implemented by a ReadWriter whose WriteBytes rejects frames
// larger than MaxFrameSize bytes. A Channel checks the sealed size against it
// before encrypting, so a frame the ReadWriter cannot carry is rejected with
// ErrFrameTooLarge and does not break the Channel. A non-positive value means
// no limit.
type FrameLimiter interface {
	MaxFrameSize() int
}

// Channel is an HPKE-encrypted, ordered frame channel over a ReadWriter.
// Every frame written consumes one HPKE sequence number, so a write that
// fails after encryption is fatal: the Channel closes the ReadWriter (when it
// implements io.Closer) and returns ErrChannelBroken from every later write.
//
// Channel implements FrameLimiter, so a ReadWriter built on a Channel can
// report the limit of the transport underneath.
type Channel struct {
	conn      ReadWriter
	sender    *hpke.Sender
	recipient *hpke.Recipient
	writeErr  error
	writeMu   sync.Mutex
}

func newChannel(
	conn ReadWriter, sender *hpke.Sender, recipient *hpke.Recipient,
) *Channel {
	return &Channel{
		conn:      conn,
		sender:    sender,
		recipient: recipient,
	}
}

func (ch *Channel) ReadBytes() ([]byte, error) {
	encrypted, err := ch.conn.ReadBytes()
	if err != nil {
		return nil, fmt.Errorf("read encrypted: %w", err)
	}
	data, err := ch.recipient.Open(nil, encrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	return data, nil
}

func (ch *Channel) WriteBytes(data []byte) error {
	return ch.WriteBytesWithin(data, 0)
}

// WriteBytesWithin writes data while holding writeMu. A positive timeout
// arms the connection write deadline for that write only, and clears it
// before the lock is released, so a concurrent writer cannot cancel it.
//
// A frame larger than the ReadWriter's FrameLimiter allows is rejected with
// ErrFrameTooLarge before encryption. Any other write failure breaks the
// Channel; see Channel.
func (ch *Channel) WriteBytesWithin(data []byte, timeout time.Duration) error {
	ch.writeMu.Lock()
	broke, err := ch.writeLocked(data, timeout)
	ch.writeMu.Unlock()

	if broke {
		// Close outside writeMu: closing a WebSocket runs a close handshake
		// that can block, and the sticky writeErr already fails the writers
		// waiting for the lock.
		_ = ch.Close()
	}
	return err
}

// writeLocked seals and writes one frame. broke reports whether this call
// broke the Channel, in which case the caller must close it. Caller must hold
// ch.writeMu.
func (ch *Channel) writeLocked(
	data []byte, timeout time.Duration,
) (broke bool, err error) {
	if ch.writeErr != nil {
		return false, ch.writeErr
	}
	if l, ok := ch.conn.(FrameLimiter); ok {
		limit := l.MaxFrameSize()
		if size := len(data) + Overhead; limit > 0 && size > limit {
			return false, fmt.Errorf(
				"%w: %d bytes, limit %d", ErrFrameTooLarge, size, limit,
			)
		}
	}

	if timeout > 0 {
		_ = ch.SetWriteDeadline(time.Now().Add(timeout))
		defer func() { _ = ch.SetWriteDeadline(time.Time{}) }()
	}

	encrypted, err := ch.sender.Seal(nil, data)
	if err != nil {
		return false, fmt.Errorf("encrypting: %w", err)
	}
	if err = ch.conn.WriteBytes(encrypted); err != nil {
		// The peer will expect the sequence number this frame used, so no
		// later frame can be opened. Fail every later write and have the
		// caller close the connection so that the peer and local readers see
		// the session end.
		ch.writeErr = fmt.Errorf("%w: %w", ErrChannelBroken, err)
		return true, fmt.Errorf("write encrypted: %w", ch.writeErr)
	}

	return false, nil
}

// MaxFrameSize reports the largest frame WriteBytes accepts: the
// ReadWriter's FrameLimiter limit less Overhead, and never less than 1. It
// reports 0 (no limit) when the ReadWriter has no limit.
func (ch *Channel) MaxFrameSize() int {
	l, ok := ch.conn.(FrameLimiter)
	if !ok {
		return 0
	}
	limit := l.MaxFrameSize()
	if limit <= 0 {
		return 0
	}
	return max(limit-Overhead, 1)
}

func (ch *Channel) Close() error {
	if c, ok := ch.conn.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

func (ch *Channel) SetDeadline(t time.Time) error {
	if d, ok := ch.conn.(interface{ SetDeadline(time.Time) error }); ok {
		return d.SetDeadline(t)
	}
	return nil
}

func (ch *Channel) SetWriteDeadline(t time.Time) error {
	if d, ok := ch.conn.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return d.SetWriteDeadline(t)
	}
	return nil
}

func Initiate(c ReadWriter) (*Channel, error) {
	kem := hpkeKEM()
	kdf := hpkeKDF()
	aead := hpkeAEAD()

	privateKey, err := kem.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generating kem key: %w", err)
	}
	if err := c.WriteBytes(privateKey.PublicKey().Bytes()); err != nil {
		return nil, fmt.Errorf("writing hpke public key: %w", err)
	}

	merged, err := c.ReadBytes()
	if err != nil {
		return nil, fmt.Errorf("reading merged message: %w", err)
	}
	remoteEnc, remotePublicBytes, err := parseMergedExchange(merged)
	if err != nil {
		return nil, err
	}

	recipient, err := hpke.NewRecipient(remoteEnc, privateKey, kdf, aead, nil)
	if err != nil {
		return nil, fmt.Errorf("creating recipient: %w", err)
	}
	remotePublic, err := kem.NewPublicKey(remotePublicBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing remote public key: %w", err)
	}
	enc, sender, err := hpke.NewSender(remotePublic, kdf, aead, nil)
	if err != nil {
		return nil, fmt.Errorf("creating sender: %w", err)
	}
	if err := c.WriteBytes(enc); err != nil {
		return nil, fmt.Errorf("writing ciphertext: %w", err)
	}

	return newChannel(c, sender, recipient), nil
}

func parseMergedExchange(merged []byte) ([]byte, []byte, error) {
	if len(merged) < 2 {
		return nil, nil, fmt.Errorf("truncated exchange: %d bytes", len(merged))
	}
	encLen := binary.BigEndian.Uint16(merged[:2])
	if int(encLen) > len(merged)-2 {
		return nil, nil, fmt.Errorf(
			"truncated ciphertext: declared %d, total %d", encLen, len(merged),
		)
	}
	remoteEnc := merged[2 : 2+encLen]
	remotePublicBytes := merged[2+encLen:]
	return remoteEnc, remotePublicBytes, nil
}

func Accept(c ReadWriter) (*Channel, error) {
	kem := hpkeKEM()
	kdf := hpkeKDF()
	aead := hpkeAEAD()

	remotePubBytes, err := c.ReadBytes()
	if err != nil {
		return nil, fmt.Errorf("reading remote public key: %w", err)
	}
	remotePub, err := kem.NewPublicKey(remotePubBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing remote public key: %w", err)
	}
	enc, sender, err := hpke.NewSender(remotePub, kdf, aead, nil)
	if err != nil {
		return nil, fmt.Errorf("creating sender: %w", err)
	}

	privateKey, err := kem.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generating kem key: %w", err)
	}
	pubB := privateKey.PublicKey().Bytes()

	merged := make([]byte, 2+len(enc)+len(pubB))
	binary.BigEndian.PutUint16(merged, uint16(len(enc)))
	copy(merged[2:], enc)
	copy(merged[2+len(enc):], pubB)
	if err := c.WriteBytes(merged); err != nil {
		return nil, fmt.Errorf("writing merged exchange message: %w", err)
	}

	remoteEnc, err := c.ReadBytes()
	if err != nil {
		return nil, fmt.Errorf("reading remote ciphertext: %w", err)
	}
	recipient, err := hpke.NewRecipient(remoteEnc, privateKey, kdf, aead, nil)
	if err != nil {
		return nil, fmt.Errorf("creating recipient: %w", err)
	}

	return newChannel(c, sender, recipient), nil
}
