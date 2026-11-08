package relayleg

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha512"
	"reflect"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractShared(t *testing.T) {
	a := require.New(t)
	relay, err := GenerateKey()
	a.NoError(err)
	peer, err := ecdh.X25519().GenerateKey(rand.Reader)
	a.NoError(err)
	peerPub := peer.PublicKey().Bytes()

	t.Run("bad domain", func(t *testing.T) {
		tests := []struct {
			name   string
			domain string
		}{
			{name: "empty", domain: ""},
			{name: "other", domain: "relayleg"},
			{name: "version 1", domain: "kamune broker v1"},
			{name: "truncated", domain: "kamune broker v"},
			{name: "upper", domain: "KAMUNE BROKER V2 dh "},
			{name: "leading space", domain: " kamune broker v2 dh "},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				a := require.New(t)
				_, err := relay.ExtractShared(tt.domain, peerPub)
				a.ErrorIs(err, ErrKeyUsage)
			})
		}
	})

	const domain = "kamune broker v2 dh "
	t.Run("matches peer", func(t *testing.T) {
		a := require.New(t)
		got, err := relay.ExtractShared(domain, peerPub)
		a.NoError(err)

		rpub, err := relay.PublicKey().ECDH()
		a.NoError(err)
		// Peer scalar with the relay public key. The DH output
		// matches the relay side.
		dh, err := peer.ECDH(rpub)
		a.NoError(err)
		pk := relay.PublicKey()
		salt := append([]byte(domain), pk[:]...)
		// Extract(hash, secret, salt): secret is the ikm.
		want, err := hkdf.Extract(sha512.New, dh, salt)
		a.NoError(err)
		a.Equal(want, got)

		exact, err := relay.ExtractShared(brokerDomain, peerPub)
		a.NoError(err)
		a.NotEqual(got, exact)
	})

	t.Run("domains differ", func(t *testing.T) {
		a := require.New(t)
		first, err := relay.ExtractShared(domain, peerPub)
		a.NoError(err)
		second, err := relay.ExtractShared(domain+"x", peerPub)
		a.NoError(err)
		a.NotEqual(first, second)
	})

	t.Run("low order", func(t *testing.T) {
		a := require.New(t)
		_, err := relay.ExtractShared(domain, make([]byte, rawKeyLen))
		a.Error(err)
		a.NotErrorIs(err, ErrKeyUsage)
	})

	t.Run("short peer", func(t *testing.T) {
		a := require.New(t)
		_, err := relay.ExtractShared(domain, []byte{1, 2, 3})
		a.Error(err)
		a.NotErrorIs(err, ErrKeyUsage)
	})
}

func TestPrivateKeyExportedMethods(t *testing.T) {
	a := require.New(t)
	typ := reflect.TypeOf((*PrivateKey)(nil))
	names := make([]string, 0, typ.NumMethod())
	for i := range typ.NumMethod() {
		names = append(names, typ.Method(i).Name)
	}
	sort.Strings(names)
	a.Equal([]string{"ExtractShared", "PublicKey"}, names)
}
