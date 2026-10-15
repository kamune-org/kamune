package kamune

import (
	"bytes"
	"context"
	"crypto/hpke"
	"crypto/rand"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/pkg/storage"
)

// validClientHello returns one ClientHello the server can parse.
func validClientHello(t testing.TB) []byte {
	t.Helper()
	a := require.New(t)
	k, err := hpke.MLKEM768X25519().GenerateKey()
	a.NoError(err)
	nonce := make([]byte, helloNonceLen)
	tag := make([]byte, helloNonceLen)
	_, err = rand.Read(nonce)
	a.NoError(err)
	_, err = rand.Read(tag)
	a.NoError(err)
	ch, err := writeClientHello(nil, nonce, tag, k.PublicKey().Bytes())
	a.NoError(err)
	return ch
}

// FuzzServerServe sends arbitrary bytes to Server.serve after a valid
// ClientHello. serve must reject every input without a panic and without
// reaching the handler.
func FuzzServerServe(f *testing.F) {
	a := require.New(f)
	store := newTransportTestStorage(f)
	var handled atomic.Bool
	server, err := NewServer(
		"",
		func(*Transport) error {
			handled.Store(true)
			return nil
		},
		store,
		func(context.Context, *storage.Storage, VerifyRequest) error {
			return nil
		},
		ServeWithIntroTimeout(5*time.Second),
	)
	a.NoError(err)
	server.handshakeOpts.timeout = 5 * time.Second

	hello := validClientHello(f)
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 4, 1, 2, 3, 4})
	f.Add(bytes.Repeat([]byte{0xff}, 64))
	f.Add(hello)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64*1024 {
			t.Skip()
		}
		a := require.New(t)
		c1, c2 := net.Pipe()
		serveErr := make(chan error, 1)
		go func() {
			serveErr <- server.serve(newConn(c2))
		}()
		go func() {
			_, _ = io.Copy(io.Discard, c1)
		}()

		client := newConn(c1)
		a.NoError(client.WriteBytes(validClientHello(t)))
		if len(data) > 0 {
			_ = client.WriteBytes(data)
		}
		_ = c1.Close()

		err := <-serveErr
		_ = c1.Close()
		a.Error(err)
		a.NotContains(err.Error(), "serve panic")
		a.False(handled.Load(), "the handler ran")
	})
}
