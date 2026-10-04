package attest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAttest(t *testing.T) {
	a := require.New(t)
	msg := []byte(rand.Text())

	e, err := New()
	a.NoError(err)
	a.NotNil(e)
	pub := e.MarshalPublicKey()
	sig, err := e.Sign(msg)
	a.NoError(err)
	a.NotNil(sig)

	id := Attest{}
	t.Run("valid signature", func(t *testing.T) {
		verified := id.Verify(pub, msg, sig)
		a.True(verified)
	})
	t.Run("invalid signature", func(t *testing.T) {
		sig := slices.Clone(sig)
		sig[0] ^= 0xFF

		verified := id.Verify(pub, msg, sig)
		a.False(verified)
	})
	t.Run("invalid hash", func(t *testing.T) {
		msg = append(msg, []byte("!")...)

		verified := id.Verify(pub, msg, sig)
		a.False(verified)
	})
	t.Run("invalid public key", func(t *testing.T) {
		another, err := New()
		a.NoError(err)
		verified := id.Verify(another.MarshalPublicKey(), msg, sig)
		a.False(verified)
	})
}

// pkixKey wraps a raw 32-byte Ed25519 public key in PKIX DER, as
// MarshalPublicKey does.
func pkixKey(t *testing.T, raw []byte) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(raw))
	require.New(t).NoError(err)
	return der
}

// rawPoint returns the 32-byte little-endian encoding given in hex, with
// the top bit, the sign of x, set when negative is true.
func rawPoint(t *testing.T, h string, negative bool) []byte {
	t.Helper()
	b, err := hex.DecodeString(h)
	require.New(t).NoError(err)
	require.New(t).Len(b, ed25519.PublicKeySize)
	if negative {
		b[31] |= 0x80
	}
	return b
}

func TestIsValidPublicKey(t *testing.T) {
	const (
		identity  = "0100000000000000000000000000000000000000000000000000000000000000"
		order2    = "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
		order4    = "0000000000000000000000000000000000000000000000000000000000000000"
		order8a   = "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"
		order8b   = "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"
		zeroPlusP = "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
		onePlusP  = "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
		// y = 3 is on the curve with a point of large order; y = p + 3 is
		// a second, non-canonical encoding of it.
		three      = "0300000000000000000000000000000000000000000000000000000000000000"
		threePlusP = "f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
		// No point on the curve has y = 2.
		offCurve = "0200000000000000000000000000000000000000000000000000000000000000"
		base     = "5866666666666666666666666666666666666666666666666666666666666666"
	)
	tests := []struct {
		name     string
		point    string
		negative bool
		valid    bool
	}{
		{"base point", base, false, true},
		{"large order", three, false, true},
		{"large order, negative x", three, true, true},
		{"identity", identity, false, false},
		{"identity, sign bit set", identity, true, false},
		{"order 2", order2, false, false},
		{"order 2, sign bit set", order2, true, false},
		{"order 4", order4, false, false},
		{"order 4, negative x", order4, true, false},
		{"order 8", order8a, false, false},
		{"order 8, negative x", order8a, true, false},
		{"order 8, other y", order8b, false, false},
		{"order 8, other y, negative x", order8b, true, false},
		{"non-canonical order 4", zeroPlusP, false, false},
		{"non-canonical identity", onePlusP, false, false},
		{"non-canonical large order", threePlusP, false, false},
		{"not on the curve", offCurve, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			key := pkixKey(t, rawPoint(t, tt.point, tt.negative))
			a.Equal(tt.valid, IsValidPublicKey(key))
		})
	}

	t.Run("generated keys", func(t *testing.T) {
		a := require.New(t)
		for range 100 {
			at, err := New()
			a.NoError(err)
			a.True(IsValidPublicKey(at.MarshalPublicKey()))
		}
	})
}

// TestVerifyRejectsSmallOrderKey checks the forgery that a small-order key
// allows: under the identity key, R = identity and S = 0 satisfy the
// cofactorless verification equation for every message.
func TestVerifyRejectsSmallOrderKey(t *testing.T) {
	a := require.New(t)
	raw := make([]byte, ed25519.PublicKeySize)
	raw[0] = 1
	sig := make([]byte, ed25519.SignatureSize)
	sig[0] = 1

	for _, msg := range []string{"hello", "any other message"} {
		a.True(ed25519.Verify(raw, []byte(msg), sig))
		a.False(Verify(pkixKey(t, raw), []byte(msg), sig))
	}
}
