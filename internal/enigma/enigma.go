package enigma

import (
	"crypto/cipher"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unsafe"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	nonceSize     = chacha20poly1305.NonceSize
	uint64Size    = int(unsafe.Sizeof(uint64(0)))
	BaseNonceSize = nonceSize - uint64Size
)

var (
	ErrInvalidNonceLength = errors.New("bad nonce length")

	C2S    = "client-to-server-cipher"
	S2C    = "server-to-client-cipher"
	hasher = sha512.New
)

type Enigma struct {
	aead      cipher.AEAD
	baseNonce []byte
}

func NewEnigma(secret, baseNonce []byte, info string) (*Enigma, error) {
	if len(baseNonce) != BaseNonceSize {
		return nil, ErrInvalidNonceLength
	}
	r := hkdf.Expand(hasher, secret, []byte(info))
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("chacha20poly1305: %w", err)
	}

	return &Enigma{aead: aead, baseNonce: baseNonce}, nil
}

func (e *Enigma) Encrypt(plaintext []byte, counter uint64) []byte {
	return e.aead.Seal(nil, e.nonce(counter), plaintext, nil)
}

func (e *Enigma) Decrypt(ciphertext []byte, counter uint64) ([]byte, error) {
	return e.aead.Open(nil, e.nonce(counter), ciphertext, nil)
}

func (e *Enigma) nonce(counter uint64) []byte {
	nonce := make([]byte, nonceSize)
	copy(nonce[:BaseNonceSize], e.baseNonce)
	binary.LittleEndian.PutUint64(nonce[BaseNonceSize:], counter)
	return nonce
}
