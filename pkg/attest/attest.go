// Package attest provides Ed25519 identity management for the kamune protocol.
// It handles key generation, signing, verification, and serialization
// (PKIX/SPKI for public keys, PKCS8 for private keys).
package attest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
)

var (
	ErrInvalidKey = errors.New("invalid key type")
)

// Attest represents the peer's identity.
type Attest struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

func (e Attest) Sign(msg []byte) ([]byte, error) {
	return ed25519.Sign(e.privateKey, msg), nil
}

func (Attest) Verify(remote, msg, sig []byte) bool {
	return Verify(remote, msg, sig)
}

func (e Attest) MarshalPublicKey() []byte {
	b, err := x509.MarshalPKIXPublicKey(e.publicKey)
	if err != nil {
		panic(fmt.Errorf("marshalling public key: %w", err))
	}
	return b
}

func (e Attest) EncodePublicKey() string {
	return base64.RawURLEncoding.EncodeToString(e.MarshalPublicKey())
}

func (e Attest) MarshalPrivateKey() ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(e.privateKey)
}

func New() (*Attest, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Attest{privateKey: private, publicKey: public}, nil
}

func Load(data []byte) (*Attest, error) {
	key, err := x509.ParsePKCS8PrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("parsing key: %w", err)
	}
	private, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	return &Attest{
		privateKey: private,
		publicKey:  private.Public().(ed25519.PublicKey),
	}, nil
}

// Verify reports whether sig is a valid signature of msg by remote, a
// PKIX-encoded Ed25519 public key. It reports false for a key that
// [IsValidPublicKey] rejects.
//
// Verify runs for every message, so it leaves the check that the point is
// on the curve, the costly one, to [ed25519.Verify], which fails for such
// a key.
func Verify(remote, msg, sig []byte) bool {
	p, err := parsePublicKey(remote)
	if err == nil {
		return ed25519.Verify(p, msg, sig)
	}
	return false
}

// IsValidPublicKey reports whether b is a PKIX-encoded Ed25519 public key
// that holds the canonical encoding of a point on the curve whose order is
// not small.
//
// Keys from [ed25519.GenerateKey] always pass. A point of small order would
// let anyone forge signatures under the key: for the identity point one
// signature verifies for every message. A non-canonical encoding names the
// same point as the canonical one, so one key would have several
// encodings, and thus several peer IDs and fingerprints.
func IsValidPublicKey(b []byte) bool {
	p, err := parsePublicKey(b)
	return err == nil && onCurve(p)
}

func parsePublicKey(key []byte) (ed25519.PublicKey, error) {
	pk, err := x509.ParsePKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	edPub, ok := pk.(ed25519.PublicKey)
	if !ok {
		return nil, ErrInvalidKey
	}
	if err := checkPoint(edPub); err != nil {
		return nil, err
	}
	return edPub, nil
}

// pointSize is the size of an encoded Ed25519 point (RFC 8032, 5.1.2): the
// y-coordinate in little-endian order, with the sign of x in the top bit.
const pointSize = ed25519.PublicKeySize

var (
	// fieldP is the prime 2^255 - 19 of the Ed25519 field.
	fieldP = new(big.Int).Sub(
		new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19),
	)

	// curveD is the constant d = -121665/121666 of the Ed25519 curve.
	curveD = func() *big.Int {
		d := new(big.Int).ModInverse(big.NewInt(121666), fieldP)
		d.Mul(d, big.NewInt(-121665))
		return d.Mod(d, fieldP)
	}()

	// order8Y is the y-coordinate of two of the four points of order 8. The
	// other two have y = p - order8Y.
	order8Y, _ = new(big.Int).SetString(
		"2707385501144840649318225287225658788936804267575313519463743609"+
			"750303402022",
		10,
	)

	// smallOrderY holds the canonical encodings, sign bit cleared, of the
	// y-coordinates of the eight points whose order divides 8: 1 for the
	// identity, p - 1 for the point of order 2, 0 for the two points of
	// order 4, and order8Y and p - order8Y for the four points of order 8.
	smallOrderY = [][pointSize]byte{
		encodeY(big.NewInt(1)),
		encodeY(new(big.Int).Sub(fieldP, big.NewInt(1))),
		encodeY(big.NewInt(0)),
		encodeY(order8Y),
		encodeY(new(big.Int).Sub(fieldP, order8Y)),
	}

	// encodedP is p in little-endian order.
	encodedP = encodeY(fieldP)
)

// encodeY returns y, which must be below 2^255, in little-endian order.
func encodeY(y *big.Int) [pointSize]byte {
	var out [pointSize]byte
	y.FillBytes(out[:])
	for i, j := 0, pointSize-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// checkPoint returns an error wrapping [ErrInvalidKey] when key is a
// non-canonical encoding of a y-coordinate or the encoding of a point of
// small order. It does not check that the point is on the curve (see
// [onCurve]), nor that it is in the prime-order subgroup.
func checkPoint(key ed25519.PublicKey) error {
	var y [pointSize]byte
	copy(y[:], key)
	y[pointSize-1] &= 0x7f

	// Every y >= p is the non-canonical encoding of y - p. RFC 8032 also
	// rejects x = 0 with the sign bit set, which is only true of the points
	// with y = 1 or y = p - 1; both have small order.
	if !belowP(y) {
		return fmt.Errorf("%w: non-canonical point encoding", ErrInvalidKey)
	}
	for _, s := range smallOrderY {
		if y == s {
			return fmt.Errorf("%w: point of small order", ErrInvalidKey)
		}
	}
	return nil
}

// belowP reports whether y, in little-endian order, is below p.
func belowP(y [pointSize]byte) bool {
	for i := pointSize - 1; i >= 0; i-- {
		if y[i] != encodedP[i] {
			return y[i] < encodedP[i]
		}
	}
	return false
}

// onCurve reports whether key, which checkPoint accepted, encodes a point
// on the curve -x^2 + y^2 = 1 + d x^2 y^2: whether x^2 = (y^2 - 1)/(d y^2 + 1)
// has a solution for its y. Since d is not a square, d y^2 + 1 is never
// zero.
func onCurve(key ed25519.PublicKey) bool {
	var be [pointSize]byte
	for i := range pointSize {
		be[i] = key[pointSize-1-i]
	}
	be[0] &= 0x7f
	y := new(big.Int).SetBytes(be[:])
	y2 := new(big.Int).Mul(y, y)
	u := new(big.Int).Sub(y2, big.NewInt(1))
	v := y2.Mul(y2, curveD)
	v.Add(v, big.NewInt(1))
	// u/v is a square exactly when u*v is.
	uv := u.Mul(u, v)
	uv.Mod(uv, fieldP)
	return big.Jacobi(uv, fieldP) >= 0
}
