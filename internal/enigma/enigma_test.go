package enigma_test

import (
	"bytes"
	"crypto/rand"
	mathrand "math/rand/v2"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/internal/enigma"
)

const benchSizePool = 1_000

func TestNewFromKey_SealOpen(t *testing.T) {
	a := require.New(t)
	key := bytes.Repeat([]byte{0x07}, 32)
	e, err := enigma.NewFromKey(key)
	a.NoError(err)
	nonce := bytes.Repeat([]byte{0x08}, 24)
	ad := []byte("kamune/2 hs")
	pt := []byte("plaintext")
	ct, err := e.Seal(nonce, pt, ad)
	a.NoError(err)
	got, err := e.Open(nonce, ct, ad)
	a.NoError(err)
	a.Equal(pt, got)

	_, err = enigma.NewFromKey(key[:31])
	a.Error(err)
	_, err = e.Seal(nonce[:23], pt, ad)
	a.Error(err)
	_, err = e.Open(nonce, ct, []byte("other"))
	a.Error(err)
}

func TestChaCha20Poly1305(t *testing.T) {
	var (
		a      = require.New(t)
		secret = []byte(rand.Text())
		salt   = []byte(rand.Text())
		info   = []byte(rand.Text())
		msg    = []byte(rand.Text())
	)

	cipher, err := enigma.NewEnigma(secret, salt, info)
	a.NoError(err)
	a.NotNil(cipher)

	encrypted := cipher.Encrypt(msg)
	a.NotNil(encrypted)
	a.NotEqual(msg, encrypted)

	decrypted, err := cipher.Decrypt(encrypted)
	a.NoError(err)
	a.NotNil(decrypted)
	a.Equal(msg, decrypted)

	secondEncryption := cipher.Encrypt(msg)
	a.NotEqual(msg, secondEncryption)
}

func TestAssociatedData(t *testing.T) {
	a := require.New(t)
	cipher, err := enigma.NewEnigma(
		[]byte(rand.Text()), []byte(rand.Text()), []byte(rand.Text()),
	)
	a.NoError(err)
	msg := []byte("bound")
	ad := []byte("peers/key")
	sealed := cipher.EncryptWithAD(msg, ad)

	cases := []struct {
		name string
		ad   []byte
		ok   bool
	}{
		{"same ad", ad, true},
		{"other ad", []byte("peers/other"), false},
		{"no ad", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			got, err := cipher.DecryptWithAD(sealed, tc.ad)
			if !tc.ok {
				a.Error(err)
				return
			}
			a.NoError(err)
			a.Equal(msg, got)
		})
	}

	// Encrypt uses empty associated data, so its output opens only without
	// any.
	plain := cipher.Encrypt(msg)
	_, err = cipher.DecryptWithAD(plain, ad)
	a.Error(err)
	got, err := cipher.DecryptWithAD(plain, nil)
	a.NoError(err)
	a.Equal(msg, got)
}

func BenchmarkEnigma_NewEnigma(b *testing.B) {
	var (
		secret = []byte(rand.Text())
		salt   = []byte(rand.Text())
		info   = []byte(rand.Text())
	)

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, _ = enigma.NewEnigma(secret, salt, info)
	}
}

func BenchmarkEnigma_Encrypt(b *testing.B) {
	var (
		secret = []byte(rand.Text())
		salt   = []byte(rand.Text())
		info   = []byte(rand.Text())
	)
	messages := make([][]byte, benchSizePool)
	for i := range messages {
		messages[i] = []byte(rand.Text())
	}
	cipher, _ := enigma.NewEnigma(secret, salt, info)

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = cipher.Encrypt(messages[mathrand.IntN(benchSizePool)])
	}
}

func BenchmarkEnigma_Decrypt(b *testing.B) {
	var (
		secret = []byte(rand.Text())
		salt   = []byte(rand.Text())
		info   = []byte(rand.Text())
	)
	cipher, _ := enigma.NewEnigma(secret, salt, info)
	messages := make([][]byte, benchSizePool)
	for i := range messages {
		messages[i] = cipher.Encrypt([]byte(rand.Text()))
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, _ = cipher.Decrypt(messages[mathrand.IntN(benchSizePool)])
	}
}
