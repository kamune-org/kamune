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

// Encrypt seals plaintext under a random nonce with no associated data. The
// result is the nonce followed by the ciphertext.
func (e *Enigma) Encrypt(plaintext []byte) []byte {
	return e.EncryptWithAD(plaintext, nil)
}

// Decrypt opens a ciphertext made by [Enigma.Encrypt].
func (e *Enigma) Decrypt(ciphertext []byte) ([]byte, error) {
	return e.DecryptWithAD(ciphertext, nil)
}

// EncryptWithAD seals plaintext under a random nonce and authenticates ad
// with it. The ciphertext opens only with the same ad, so ad can bind it to
// a context, such as where it is stored. ad itself is not included.
func (e *Enigma) EncryptWithAD(plaintext, ad []byte) []byte {
	nonce := make(
		[]byte, nonceSize, nonceSize+len(plaintext)+e.aead.Overhead(),
	)
	if _, err := rand.Read(nonce); err != nil {
		panic("enigma: crypto/rand: " + err.Error())
	}
	return e.aead.Seal(nonce, nonce, plaintext, ad)
}

// DecryptWithAD opens a ciphertext made by [Enigma.EncryptWithAD] with the
// same ad.
func (e *Enigma) DecryptWithAD(ciphertext, ad []byte) ([]byte, error) {
	if len(ciphertext) < nonceSize {
		return nil, ErrInvalidCiphertext
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := e.aead.Open(nil, nonce, ciphertext, ad)
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

// Text returns a random string of length l in the RFC 4648 base32
// alphabet: the capital letters A to Z and the digits 2 to 7. The digits
// 0, 1, 8 and 9 are left out, but the letters O and I are not, so the text
// can still hold characters that look like 0 and 1. Each byte comes from
// crypto/rand and is mapped to a character by its value modulo 32, which
// favours none, as 256 is a multiple of 32.
func Text(l int) string {
	src := make([]byte, l)
	if _, err := rand.Read(src); err != nil {
		panic("enigma: crypto/rand: " + err.Error())
	}
	for i := range src {
		src[i] = base32alphabet[src[i]%32]
	}
	return string(src)
}
