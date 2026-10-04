package kamune

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/internal/enigma"
	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/storage"
)

// recordConn records the frames written to it.
type recordConn struct {
	queuedConn
	written [][]byte
}

func (c *recordConn) WriteBytes(b []byte) error {
	c.written = append(c.written, bytes.Clone(b))
	return nil
}

// recordFrame returns the frame that send writes.
func recordFrame(f *testing.F, send func(Conn) error) []byte {
	f.Helper()
	a := require.New(f)
	rc := &recordConn{}
	a.NoError(send(rc))
	a.Len(rc.written, 1)
	return rc.written[0]
}

// FuzzServerServe sends arbitrary bytes to Server.serve over a pipe: as the
// first bytes on the connection, or after a real key exchange as the first
// message, where the dialer's introduction or resume request belongs. serve
// must reject every input without a panic, without reaching the handler and
// without consuming the stored session's resumption token.
func FuzzServerServe(f *testing.F) {
	a := require.New(f)
	store, cleanup := newTestStore(f)
	f.Cleanup(cleanup)
	client, err := attest.New()
	a.NoError(err)
	other, err := attest.New()
	a.NoError(err)
	a.NoError(store.StorePeer(&storage.Peer{
		Name:      "client",
		PublicKey: client.MarshalPublicKey(),
		FirstSeen: time.Now(),
	}))
	sessionID := enigma.Text(sessionIDLength)
	token := bytes.Repeat([]byte{0x42}, resumptionTokenSize)
	a.NoError(store.PutSessionResumption(
		sessionID, client.MarshalPublicKey(), [][]byte{token}, true,
	))
	tokens, err := store.GetMeta(sessionID, storage.ResumptionTokensKey)
	a.NoError(err)

	var handled atomic.Bool
	server, err := NewServer(
		"",
		func(*Transport) error {
			handled.Store(true)
			return nil
		},
		store,
		func(*storage.Storage, *storage.Peer) error {
			return errors.New("rejected by the fuzz verifier")
		},
		ServeWithIntroTimeout(5*time.Second),
	)
	a.NoError(err)
	server.handshakeOpts.timeout = 5 * time.Second

	f.Add(false, []byte{})
	f.Add(false, []byte{0, 0, 0, 4, 1, 2, 3, 4})
	f.Add(false, bytes.Repeat([]byte{0xff}, 64))
	f.Add(true, []byte{})
	f.Add(true, []byte{0x0a, 0x02, 0x08, 0x01})
	f.Add(true, recordFrame(f, func(c Conn) error {
		return sendIntroduction(c, other, "fuzz", AppVersion)
	}))
	// A resume request with the stored token, signed by the wrong key.
	f.Add(true, recordFrame(f, func(c Conn) error {
		return sendResumeRequest(c, other, sessionID, token)
	}))
	// A resume request signed by the client, for a token not stored.
	f.Add(true, recordFrame(f, func(c Conn) error {
		return sendResumeRequest(
			c, client, sessionID, bytes.Repeat([]byte{0x24}, len(token)),
		)
	}))

	f.Fuzz(func(t *testing.T, exchanged bool, data []byte) {
		if len(data) > 64*1024 {
			t.Skip()
		}
		a := require.New(t)
		c1, c2 := net.Pipe()
		serveErr := make(chan error, 1)
		go func() {
			serveErr <- server.serve(newConn(c2))
		}()

		// Read whatever the server sends, so that its writes never block,
		// until it closes the connection.
		drained := make(chan struct{})
		if exchanged {
			clientConn := newConn(c1)
			ec, err := exchange.Initiate(clientConn)
			a.NoError(err)
			go func() {
				defer close(drained)
				for {
					if _, err := ec.ReadBytes(); err != nil {
						return
					}
				}
			}()
			_ = ec.WriteBytes(data)
		} else {
			go func() {
				defer close(drained)
				_, _ = io.Copy(io.Discard, c1)
			}()
			_, _ = c1.Write(data)
			// The input may end part-way through a frame.
			_ = c1.Close()
		}

		err := <-serveErr
		_ = c1.Close()
		<-drained
		a.Error(err)
		a.NotContains(err.Error(), "serve panic")
		a.False(handled.Load(), "the handler ran")
		after, err := store.GetMeta(sessionID, storage.ResumptionTokensKey)
		a.NoError(err)
		a.Equal(tokens.Value(), after.Value(), "a token was consumed")
	})
}
