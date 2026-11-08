package relayleg

import (
	"bytes"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPrivateKeyFileRoundTrip(t *testing.T) {
	a := require.New(t)
	path := filepath.Join(t.TempDir(), "relay-static-key.pem")
	k, err := CreatePrivateKeyFile(path)
	a.NoError(err)

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		a.NoError(err)
		a.Equal(os.FileMode(0o600), info.Mode().Perm())
	}

	loaded, err := LoadPrivateKeyFile(path)
	a.NoError(err)
	a.Equal(k.PublicKey(), loaded.PublicKey())

	data, err := os.ReadFile(path)
	a.NoError(err)
	block, rest := pem.Decode(data)
	a.NotNil(block)
	a.Equal(pemType, block.Type)
	a.Empty(block.Headers)
	a.Len(block.Bytes, rawKeyLen)
	a.Empty(bytes.TrimSpace(rest))
}

func TestCreatePrivateKeyFileExists(t *testing.T) {
	a := require.New(t)
	path := filepath.Join(t.TempDir(), "relay-static-key.pem")
	const original = "original"
	a.NoError(os.WriteFile(path, []byte(original), 0o644))

	_, err := CreatePrivateKeyFile(path)
	a.Error(err)
	a.ErrorIs(err, os.ErrExist)

	got, err := os.ReadFile(path)
	a.NoError(err)
	a.Equal([]byte(original), got)
}

func TestLoadPrivateKeyFileRejects(t *testing.T) {
	body := bytes.Repeat([]byte{1}, rawKeyLen)
	valid := pem.EncodeToMemory(&pem.Block{
		Type:  pemType,
		Bytes: body,
	})
	withType := func(typ string, n int) []byte {
		return pem.EncodeToMemory(&pem.Block{
			Type:  typ,
			Bytes: bytes.Repeat([]byte{1}, n),
		})
	}
	tests := []struct {
		name string
		data []byte
	}{
		{name: "wrong type", data: withType("RSA PRIVATE KEY", rawKeyLen)},
		{name: "second block", data: append(append([]byte{}, valid...), valid...)},
		{
			name: "trailing",
			data: append(append([]byte{}, valid...), []byte("trailing\n")...),
		},
		{name: "31 bytes", data: withType(pemType, rawKeyLen-1)},
		{name: "33 bytes", data: withType(pemType, rawKeyLen+1)},
		{
			name: "headers",
			data: pem.EncodeToMemory(&pem.Block{
				Type:    pemType,
				Headers: map[string]string{"Foo": "bar"},
				Bytes:   body,
			}),
		},
		{name: "empty", data: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			path := filepath.Join(t.TempDir(), "k.pem")
			a.NoError(os.WriteFile(path, tt.data, 0o600))
			_, err := LoadPrivateKeyFile(path)
			a.Error(err)
			a.ErrorContains(err, path)
		})
	}
}
