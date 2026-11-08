package relayleg

import (
	"crypto/sha256"
	"encoding/base32"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseText(t *testing.T) {
	raw := sampleRaw()
	body := canonicalBody(raw[:])
	spoiled := spoilUnused(t, body)
	zeroBody := canonicalBody(make([]byte, rawKeyLen))

	// The standard decoder accepts a last character whose unused
	// bits are set, and returns the same key. This parser must not.
	stdlib := base32.StdEncoding.WithPadding(base32.NoPadding)
	decoded, err := stdlib.DecodeString(strings.ToUpper(spoiled))
	a := require.New(t)
	a.NoError(err)
	a.Equal(raw[:], decoded)

	codecs := []struct {
		name      string
		prefix    string
		sentinel  error
		parse     func(string) ([32]byte, error)
		stringify func([32]byte) string
	}{
		{
			name:     "public",
			prefix:   relayPrefix,
			sentinel: ErrInvalidRelayKey,
			parse: func(s string) ([32]byte, error) {
				k, err := ParsePublicKey(s)
				return [32]byte(k), err
			},
			stringify: func(b [32]byte) string {
				return PublicKey(b).String()
			},
		},
		{
			name:     "psk",
			prefix:   pskPrefix,
			sentinel: ErrInvalidPSK,
			parse: func(s string) ([32]byte, error) {
				p, err := ParsePSK(s)
				return [32]byte(p), err
			},
			stringify: func(b [32]byte) string {
				return PSK(b).String()
			},
		},
	}
	rows := []struct {
		name  string
		build func(prefix, body string) string
		ok    bool
	}{
		{
			name:  "canonical",
			build: func(p, b string) string { return p + b },
			ok:    true,
		},
		{
			name:  "grouped",
			build: func(p, b string) string { return groupText(p, b) },
			ok:    true,
		},
		{
			name: "upper",
			build: func(p, b string) string {
				return strings.ToUpper(p + b)
			},
			ok: true,
		},
		{
			name: "spaces",
			build: func(p, b string) string {
				return "  " + p + b + " \n"
			},
			ok: true,
		},
		{
			name: "inner space",
			build: func(p, b string) string {
				return p + b[:4] + " " + b[4:]
			},
			ok: true,
		},
		{
			name: "wrong prefix",
			build: func(p, b string) string {
				return p[:len(p)-2] + "2-" + b
			},
		},
		{
			name: "other prefix",
			build: func(p, b string) string {
				if strings.HasPrefix(p, "rk") {
					return pskPrefix + b
				}
				return relayPrefix + b
			},
		},
		{
			name: "51",
			build: func(p, b string) string {
				return p + b[:textKeyLen-1]
			},
		},
		{
			name: "53",
			build: func(p, b string) string {
				return p + b + "a"
			},
		},
		{
			name:  "empty",
			build: func(string, string) string { return "" },
		},
		{
			name: "char 0",
			build: func(p, b string) string {
				return p + replaceAt(b, 0, '0')
			},
		},
		{
			name: "char 1",
			build: func(p, b string) string {
				return p + replaceAt(b, 1, '1')
			},
		},
		{
			name: "char 8",
			build: func(p, b string) string {
				return p + replaceAt(b, 2, '8')
			},
		},
		{
			name: "bang",
			build: func(p, b string) string {
				return p + replaceAt(b, 3, '!')
			},
		},
		{
			name: "unused bits",
			build: func(p string, _ string) string {
				return p + spoiled
			},
		},
		{
			name: "all zero",
			build: func(p string, _ string) string {
				return p + zeroBody
			},
		},
	}

	for _, c := range codecs {
		t.Run(c.name, func(t *testing.T) {
			a := require.New(t)
			a.Equal(c.prefix+body, c.stringify(raw))
			for _, row := range rows {
				t.Run(row.name, func(t *testing.T) {
					a := require.New(t)
					in := row.build(c.prefix, body)
					got, err := c.parse(in)
					if !row.ok {
						a.Error(err)
						a.ErrorIs(err, c.sentinel)
						return
					}
					a.NoError(err)
					a.Equal(raw, got)
					a.Equal(c.prefix+body, c.stringify(got))
				})
			}
		})
	}
}

func TestTextRoundTrip(t *testing.T) {
	a := require.New(t)
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	for range 8 {
		k, err := GenerateKey()
		a.NoError(err)
		pk := k.PublicKey()
		body := strings.ToLower(enc.EncodeToString(pk[:]))
		a.Equal(relayPrefix+body, pk.String())
		a.Equal(groupText(relayPrefix, body), pk.Display())
		a.Len(pk.String(), len(relayPrefix)+textKeyLen)

		got, err := ParsePublicKey(pk.String())
		a.NoError(err)
		a.Equal(pk, got)
		got, err = ParsePublicKey(pk.Display())
		a.NoError(err)
		a.Equal(pk, got)

		pub, err := pk.ECDH()
		a.NoError(err)
		a.Equal(pk[:], pub.Bytes())

		p, err := GeneratePSK()
		a.NoError(err)
		pBody := strings.ToLower(enc.EncodeToString(p[:]))
		a.Equal(pskPrefix+pBody, p.String())
		a.Len(p.String(), len(pskPrefix)+textKeyLen)
		parsed, err := ParsePSK(p.String())
		a.NoError(err)
		a.Equal(p, parsed)
	}
}

func TestKeyHint(t *testing.T) {
	a := require.New(t)
	var k PublicKey
	for i := range k {
		k[i] = byte(i + 1)
	}
	sum := sha256.Sum256(append(
		[]byte("kamune relayleg v2 key hint"), k[:]...,
	))
	var want [4]byte
	copy(want[:], sum[:4])
	a.Equal(want, KeyHint(k))

	var other PublicKey
	other[0] = 0xff
	a.NotEqual(KeyHint(k), KeyHint(other))
}

func TestGeneratePSK(t *testing.T) {
	a := require.New(t)
	p, err := GeneratePSK()
	a.NoError(err)
	q, err := GeneratePSK()
	a.NoError(err)
	a.NotEqual(p, q)
	a.NotEqual(PSK{}, p)
	a.NotEqual(PSK{}, q)
}

func sampleRaw() [32]byte {
	var raw [32]byte
	for i := range raw {
		raw[i] = byte(i*7 + 3)
	}
	return raw
}

func canonicalBody(raw []byte) string {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	return strings.ToLower(enc.EncodeToString(raw))
}

func spoilUnused(t *testing.T, body string) string {
	t.Helper()
	a := require.New(t)
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	idx := strings.IndexByte(alphabet, body[len(body)-1])
	a.GreaterOrEqual(idx, 0)
	// The canonical last character carries one data bit and four
	// unused low bits, which are zero.
	a.Zero(idx & 0x0f)
	return body[:len(body)-1] + string(alphabet[idx|1])
}

func groupText(prefix, body string) string {
	var b strings.Builder
	b.WriteString(prefix)
	for i := 0; i < len(body); i += 4 {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(body[i : i+4])
	}
	return b.String()
}

func replaceAt(s string, i int, c byte) string {
	buf := []byte(s)
	buf[i] = c
	return string(buf)
}
