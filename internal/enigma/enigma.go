// Package enigma provides symmetric encryption primitives for the kamune
// protocol. It wraps XChaCha20-Poly1305 AEAD with keys derived via HKDF-SHA512,
// and provides a helper for generating random base32-encoded text.
package enigma

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	base32alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	nonceSize      = chacha20poly1305.NonceSizeX
)

var (
	ErrInvalidCiphertext = errors.New("ciphertext is not valid")
	hasher               = sha512.New
)

type Enigma struct {
	aead cipher.AEAD
}

func NewEnigma(secret, salt, info []byte) (*Enigma, error) {
	key, err := Derive(secret, salt, info, chacha20poly1305.KeySize)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("chacha20poly1305X: %w", err)
	}

	return &Enigma{aead: aead}, nil
}

func (e *Enigma) Encrypt(plaintext []byte) []byte {
	nonce := make(
		[]byte, nonceSize, nonceSize+len(plaintext)+e.aead.Overhead(),
	)
	_, _ = rand.Read(nonce)
	return e.aead.Seal(nonce, nonce, plaintext, nil)
}

func (e *Enigma) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < nonceSize {
		return nil, ErrInvalidCiphertext
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := e.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("aead.Open: %w", err)
	}

	return plaintext, nil
}

func Derive(key, salt, info []byte, size int) ([]byte, error) {
	r := hkdf.New(hasher, key, salt, info)
	d := make([]byte, size)
	if _, err := io.ReadFull(r, d); err != nil {
		return nil, err
	}
	return d, nil
}

// Text returns a random base32 string of length l (using a custom alphabet
// that excludes ambiguous characters like 0/O/1/I). Each byte is generated
// cryptographically and then mapped into the alphabet.
func Text(l int) string {
	src := make([]byte, l)
	_, _ = rand.Read(src)
	for i := range src {
		src[i] = base32alphabet[src[i]%32]
	}
	return string(src)
}
