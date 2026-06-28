package relayconn

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenFromKeys_Deterministic(t *testing.T) {
	a, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	b, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	t1, err := TokenFromKeys(a, b)
	require.NoError(t, err)
	t2, err := TokenFromKeys(a, b)
	require.NoError(t, err)

	assert.True(t, bytes.Equal(t1, t2),
		"TokenFromKeys must be deterministic for the same input pair")
}

func TestTokenFromKeys_OrderIndependent(t *testing.T) {
	a, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	b, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	t1, err := TokenFromKeys(a, b)
	require.NoError(t, err)
	t2, err := TokenFromKeys(b, a)
	require.NoError(t, err)

	assert.True(t, bytes.Equal(t1, t2),
		"TokenFromKeys(A, B) must equal TokenFromKeys(B, A)")
}

func TestTokenFromKeys_DistinctPairs(t *testing.T) {
	a, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	b, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	c, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	tab, err := TokenFromKeys(a, b)
	require.NoError(t, err)
	tac, err := TokenFromKeys(a, c)
	require.NoError(t, err)

	assert.False(t, bytes.Equal(tab, tac),
		"distinct peer pairs must produce distinct tokens")
}

func TestTokenFromKeys_Length16(t *testing.T) {
	a, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	b, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	tok, err := TokenFromKeys(a, b)
	require.NoError(t, err)

	assert.Len(t, tok, 16, "token must be exactly 16 bytes")
}

func TestTokenFromKeys_WrongSizeRejected(t *testing.T) {
	a, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	b, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	// Empty key.
	_, err = TokenFromKeys(a[:0], b)
	assert.ErrorIs(t, err, ErrInvalidKeySize)

	// Truncated key.
	_, err = TokenFromKeys(a, b[:10])
	assert.ErrorIs(t, err, ErrInvalidKeySize)

	// Oversized key.
	_, err = TokenFromKeys(a, append(b, 0x00))
	assert.ErrorIs(t, err, ErrInvalidKeySize)
}
