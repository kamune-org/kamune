package exchange

import (
	"crypto/hpke"
	"fmt"
	"io"
	"time"
)

var (
	hpkeKEM  = hpke.MLKEM768X25519
	hpkeKDF  = hpke.HKDFSHA512
	hpkeAEAD = hpke.ChaCha20Poly1305
)

type ReadWriter interface {
	ReadBytes() ([]byte, error)
	WriteBytes([]byte) error
}

type Channel struct {
	conn      ReadWriter
	sender    *hpke.Sender
	recipient *hpke.Recipient
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
	encrypted, err := ch.sender.Seal(nil, data)
	if err != nil {
		return fmt.Errorf("encrypting: %w", err)
	}
	if err = ch.conn.WriteBytes(encrypted); err != nil {
		return fmt.Errorf("write encrypted: %w", err)
	}

	return nil
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
	remoteEnc, err := c.ReadBytes()
	if err != nil {
		return nil, fmt.Errorf("reading remote ciphertext: %w", err)
	}
	recipient, err := hpke.NewRecipient(remoteEnc, privateKey, kdf, aead, nil)
	if err != nil {
		return nil, fmt.Errorf("creating recipient: %w", err)
	}

	remotePublicBytes, err := c.ReadBytes()
	if err != nil {
		return nil, fmt.Errorf("reading remote public key: %w", err)
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
	if err := c.WriteBytes(enc); err != nil {
		return nil, fmt.Errorf("writing ciphertext: %w", err)
	}

	privateKey, err := kem.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generating kem key: %w", err)
	}
	if err := c.WriteBytes(privateKey.PublicKey().Bytes()); err != nil {
		return nil, fmt.Errorf("writing hpke public key: %w", err)
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
