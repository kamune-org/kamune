package relayconn

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTokenFromKeys_Deterministic(t *testing.T) {
	a := require.New(t)
	x, _, err := ed25519.GenerateKey(nil)
	a.NoError(err)
	y, _, err := ed25519.GenerateKey(nil)
	a.NoError(err)

	t1, err := TokenFromKeys(x, y)
	a.NoError(err)
	t2, err := TokenFromKeys(x, y)
	a.NoError(err)

	a.True(bytes.Equal(t1, t2), "TokenFromKeys must be deterministic for the same input pair")
}

func TestTokenFromKeys_OrderIndependent(t *testing.T) {
	a := require.New(t)
	x, _, err := ed25519.GenerateKey(nil)
	a.NoError(err)
	y, _, err := ed25519.GenerateKey(nil)
	a.NoError(err)

	t1, err := TokenFromKeys(x, y)
	a.NoError(err)
	t2, err := TokenFromKeys(y, x)
	a.NoError(err)

	a.True(bytes.Equal(t1, t2), "TokenFromKeys(A, B) must equal TokenFromKeys(B, A)")
}

func TestTokenFromKeys_DistinctPairs(t *testing.T) {
	a := require.New(t)
	x, _, err := ed25519.GenerateKey(nil)
	a.NoError(err)
	y, _, err := ed25519.GenerateKey(nil)
	a.NoError(err)
	z, _, err := ed25519.GenerateKey(nil)
	a.NoError(err)

	tab, err := TokenFromKeys(x, y)
	a.NoError(err)
	tac, err := TokenFromKeys(x, z)
	a.NoError(err)

	a.False(bytes.Equal(tab, tac), "distinct peer pairs must produce distinct tokens")
}

func TestTokenFromKeys_Length32(t *testing.T) {
	a := require.New(t)
	x, _, err := ed25519.GenerateKey(nil)
	a.NoError(err)
	y, _, err := ed25519.GenerateKey(nil)
	a.NoError(err)

	tok, err := TokenFromKeys(x, y)
	a.NoError(err)
	a.Len(tok, 32, "token must be exactly 32 bytes")
}

func TestTokenFromKeys_WrongSizeRejected(t *testing.T) {
	a := require.New(t)
	x, _, err := ed25519.GenerateKey(nil)
	a.NoError(err)
	y, _, err := ed25519.GenerateKey(nil)
	a.NoError(err)

	_, err = TokenFromKeys(x[:0], y)
	a.ErrorIs(err, ErrInvalidKeySize)

	_, err = TokenFromKeys(x, y[:10])
	a.ErrorIs(err, ErrInvalidKeySize)

	_, err = TokenFromKeys(x, append(y, 0x00))
	a.ErrorIs(err, ErrInvalidKeySize)
}

func TestValidateUserToken_RejectsTooShort(t *testing.T) {
	a := require.New(t)
	a.ErrorIs(ValidateUserToken(nil), ErrTokenTooShort)
	a.ErrorIs(ValidateUserToken(make([]byte, 15)), ErrTokenTooShort)
	a.ErrorIs(ValidateUserToken(make([]byte, 33)), ErrTokenTooShort)
}

func TestValidateUserToken_RejectsAllZeros(t *testing.T) {
	a := require.New(t)
	a.ErrorIs(ValidateUserToken(make([]byte, 32)), ErrTokenInsufficientEntropy)
}

func TestValidateUserToken_RejectsConstantByte(t *testing.T) {
	a := require.New(t)
	a.ErrorIs(ValidateUserToken(bytes.Repeat([]byte{0xAA}, 32)), ErrTokenInsufficientEntropy)
}

func TestValidateUserToken_AcceptsHighEntropy(t *testing.T) {
	a := require.New(t)
	x, _, err := ed25519.GenerateKey(nil)
	a.NoError(err)
	y, _, err := ed25519.GenerateKey(nil)
	a.NoError(err)
	tok, err := TokenFromKeys(x, y)
	a.NoError(err)
	a.NoError(ValidateUserToken(tok))
}
