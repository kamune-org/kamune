package kamune

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func xwingPK(t *testing.T) []byte {
	t.Helper()
	a := require.New(t)
	kem := hpke.MLKEM768X25519()
	sk, err := kem.DeriveKeyPair(bytes.Repeat([]byte{0x01}, 32))
	a.NoError(err)
	pk := sk.PublicKey().Bytes()
	a.Len(pk, 1216)
	return pk
}

func identityKey(t *testing.T) []byte {
	t.Helper()
	a := require.New(t)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	a.NoError(err)
	b, err := x509.MarshalPKIXPublicKey(pub)
	a.NoError(err)
	a.Len(b, 44)
	a.Equal(
		[]byte{
			0x30, 0x2a, 0x30, 0x05, 0x06, 0x03,
			0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
		},
		b[:12],
	)
	return b
}

func TestHSFrame_RoundTrip(t *testing.T) {
	a := require.New(t)
	pk := xwingPK(t)
	idKey := identityKey(t)
	nonce := bytes.Repeat([]byte{0x11}, 32)
	tag := bytes.Repeat([]byte{0x22}, 32)
	ch, err := writeClientHello(nil, nonce, tag, pk)
	a.NoError(err)
	a.Len(ch, 1282)
	gotN, gotT, gotPK, err := parseClientHello(ch)
	a.NoError(err)
	a.Equal(nonce, gotN)
	a.Equal(tag, gotT)
	a.Equal(pk, gotPK)

	enc := bytes.Repeat([]byte{0x33}, 1120)
	sh, err := writeServerHello(nil, nonce, enc)
	a.NoError(err)
	a.Len(sh, 1154)
	gotN, gotEnc, err := parseServerHello(sh)
	a.NoError(err)
	a.Equal(nonce, gotN)
	a.Equal(enc, gotEnc)

	sig := bytes.Repeat([]byte{0x41}, 64)
	fin := bytes.Repeat([]byte{0x42}, 64)
	ra, err := encodeResponderAuth(idKey, sig, fin)
	a.NoError(err)
	a.Len(ra, 172)
	key := bytes.Repeat([]byte{0x07}, 32)
	sealed, err := sealHS(key, ra, protocolVersion, 0x03)
	a.NoError(err)
	a.Len(sealed, 214)
	opened, err := openHS(key, sealed, 0x03)
	a.NoError(err)
	a.Equal(ra, opened)
	gotKey, gotSig, gotFin, err := parseResponderAuth(opened)
	a.NoError(err)
	a.Equal(idKey, gotKey)
	a.Equal(sig, gotSig)
	a.Equal(fin, gotFin)

	id := initiatorBlock{
		Key: idKey, Name: []byte("ada"), Version: []byte("0.9.0"),
	}
	ia, err := encodeInitiatorAuth(id, nil, sig, fin)
	a.NoError(err)
	a.Len(ia, 384)
	a.Equal(byte(0), ia[len(ia)-1])
	sealed, err = sealHS(key, ia, protocolVersion, 0x04)
	a.NoError(err)
	a.Len(sealed, 426)
	opened, err = openHS(key, sealed, 0x04)
	a.NoError(err)
	gotID, gotBinder, gotSig, gotFin, err := parseInitiatorAuth(opened)
	a.NoError(err)
	a.Equal(id.Key, gotID.Key)
	a.Equal(id.Name, gotID.Name)
	a.Equal(id.Version, gotID.Version)
	a.Empty(gotID.ResumeSID)
	a.Nil(gotBinder)
	a.Equal(sig, gotSig)
	a.Equal(fin, gotFin)

	sid := []byte("AAAAAAAAAAAAAAAAAAAAAAAA")
	binder := bytes.Repeat([]byte{0x44}, 64)
	id.ResumeSID = sid
	ia, err = encodeInitiatorAuth(id, binder, sig, fin)
	a.NoError(err)
	gotID, gotBinder, _, _, err = parseInitiatorAuth(ia)
	a.NoError(err)
	a.Equal(sid, gotID.ResumeSID)
	a.Equal(binder, gotBinder)

	cf, err := encodeConfirm(1, 0, "ada", "0.9.0", fin)
	a.NoError(err)
	a.Len(cf, 192)
	sealed, err = sealHS(key, cf, protocolVersion, 0x05)
	a.NoError(err)
	a.Len(sealed, 234)
	opened, err = openHS(key, sealed, 0x05)
	a.NoError(err)
	st, reason, name, ver, gotFin, err := parseConfirm(opened)
	a.NoError(err)
	a.Equal(byte(1), st)
	a.Equal(byte(0), reason)
	a.Equal("ada", name)
	a.Equal("0.9.0", ver)
	a.Equal(fin, gotFin)

	rej, err := encodeConfirm(3, 1, "", "", fin)
	a.NoError(err)
	st, reason, name, ver, _, err = parseConfirm(rej)
	a.NoError(err)
	a.Equal(byte(3), st)
	a.Equal(byte(1), reason)
	a.Empty(name)
	a.Empty(ver)

	badPK := bytes.Repeat([]byte{0xff}, 1216)
	badHello := make([]byte, 1282)
	badHello[0] = protocolVersion
	badHello[1] = 0x01
	copy(badHello[66:], badPK)

	small := append([]byte{
		0x30, 0x2a, 0x30, 0x05, 0x06, 0x03,
		0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
	}, make([]byte, 32)...)
	flipped := append([]byte(nil), idKey...)
	flipped[0] ^= 0xff
	padded := append([]byte(nil), ia...)
	padded[len(padded)-1] = 1
	shortVer := ch[:1281]
	wrongType := append([]byte(nil), ch...)
	wrongType[1] = 0x02
	wrongVer := append([]byte(nil), ch...)
	wrongVer[0] = 0x01
	badSeal := append([]byte(nil), sealed...)
	badSeal[len(badSeal)-1] ^= 0xff
	badVerSeal := append([]byte(nil), sealed...)
	badVerSeal[0] = 0x01

	cases := []struct {
		name string
		err  error
		run  func() error
	}{
		{"wrong version", ErrUnsupportedProtocol, func() error {
			_, _, _, err := parseClientHello(wrongVer)
			return err
		}},
		{"wrong type", ErrInvalidHandshake, func() error {
			_, _, _, err := parseClientHello(wrongType)
			return err
		}},
		{"wrong length", ErrInvalidHandshake, func() error {
			_, _, _, err := parseClientHello(shortVer)
			return err
		}},
		{"ephemeral key", ErrInvalidHandshake, func() error {
			_, _, _, err := parseClientHello(badHello)
			return err
		}},
		{"pkix prefix", ErrInvalidHandshake, func() error {
			_, err := encodeResponderAuth(flipped, sig, fin)
			return err
		}},
		{"small order", ErrInvalidHandshake, func() error {
			_, err := encodeResponderAuth(small, sig, fin)
			return err
		}},
		{"peer name", ErrInvalidPeerName, func() error {
			bad := id
			bad.ResumeSID = nil
			bad.Name = []byte("ada\n")
			_, err := encodeInitiatorAuth(bad, nil, sig, fin)
			return err
		}},
		{"version length", ErrInvalidHandshake, func() error {
			bad := initiatorBlock{
				Key: idKey, Name: []byte("ada"),
				Version: []byte(strings.Repeat("1", 33)),
			}
			_, err := encodeInitiatorAuth(bad, nil, sig, fin)
			return err
		}},
		{"resume sid length", ErrInvalidHandshake, func() error {
			bad := initiatorBlock{
				Key: idKey, Name: []byte("ada"),
				Version: []byte("0.9.0"), ResumeSID: []byte("ABCDE"),
			}
			_, err := encodeInitiatorAuth(bad, nil, sig, fin)
			return err
		}},
		{"nonzero padding", ErrInvalidHandshake, func() error {
			_, _, _, _, err := parseInitiatorAuth(padded)
			return err
		}},
		{"confirm status", ErrInvalidHandshake, func() error {
			_, err := encodeConfirm(9, 0, "ada", "0.9.0", fin)
			return err
		}},
		{"binder with empty sid", ErrInvalidHandshake, func() error {
			bad := initiatorBlock{
				Key: idKey, Name: []byte("ada"), Version: []byte("0.9.0"),
			}
			_, err := encodeInitiatorAuth(bad, binder, sig, fin)
			return err
		}},
		{"binder absent", ErrInvalidHandshake, func() error {
			_, err := encodeInitiatorAuth(id, nil, sig, fin)
			return err
		}},
		{"aead", ErrVerificationFailed, func() error {
			_, err := openHS(key, badSeal, 0x05)
			return err
		}},
		{"sealed version", ErrUnsupportedProtocol, func() error {
			_, err := openHS(key, badVerSeal, 0x05)
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			a.ErrorIs(tc.run(), tc.err)
		})
	}
}
