package handlers

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/relayconn"
	"github.com/kamune-org/kamune/pkg/storage"

	"github.com/kamune-org/kamune/cmd/relay/internal/config"
	"github.com/kamune-org/kamune/cmd/relay/internal/services"
)

// largestKamuneFrame is kamune's maxFrameSize: math.MaxUint16 less the
// 64 bytes kamune reserves for a Conn, such as the relay's, that wraps
// each frame again. A message above 32 KiB is padded to it.
const largestKamuneFrame = math.MaxUint16 - 64

// relayEndpoints dials and listens on one transport of a test relay.
type relayEndpoints struct {
	listen func(context.Context) (*relayconn.ListenResult, error)
	dial   func(context.Context, []byte) (*relayconn.RelayConn, error)
}

// startTestRelay runs the relay's hub and its tcp, tls and ws handlers on
// loopback listeners with the default configuration, so frames are read
// with the default max_message_size, and returns the endpoints of each
// transport by name. Everything stops when t ends.
func startTestRelay(t *testing.T) map[string]relayEndpoints {
	t.Helper()
	a := require.New(t)
	cfg := config.Config{
		WS: config.WS{Enabled: true, Address: "127.0.0.1:0"},
		Session: config.Session{
			TokenTTL:              time.Minute,
			MaxConcurrentSessions: 10,
			HandshakeTimeout:      time.Minute,
		},
		RateLimit: config.RateLimit{Disabled: true},
	}
	ctx, cancel := context.WithCancel(context.Background())
	srvc, err := services.New(ctx, cfg)
	a.NoError(err)
	a.Equal(config.DefaultMaxMessageSize, srvc.MaxMessageSize())

	var wg sync.WaitGroup
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})
	serve := func(ln net.Listener) string {
		wg.Go(func() { acceptLoop(ctx, ln, srvc.Hub()) })
		return ln.Addr().String()
	}

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	a.NoError(err)
	tcpAddr := serve(tcpLn)

	cert := selfSigned(t)
	tlsLn, err := net.Listen("tcp", "127.0.0.1:0")
	a.NoError(err)
	tlsAddr := serve(tls.NewListener(tlsLn, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}))
	pin, err := relayconn.ParseCertFingerprint(
		relayconn.CertFingerprint(cert.Certificate[0]),
	)
	a.NoError(err)
	clientTLS, err := relayconn.PinnedTLSConfig(pin)
	a.NoError(err)

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", New(ctx, srvc, cfg).WebSocketHandler)
	wsSrv := httptest.NewServer(mux)
	t.Cleanup(wsSrv.Close)
	wsAddr := strings.TrimPrefix(wsSrv.URL, "http://")

	return map[string]relayEndpoints{
		"tcp": {
			listen: func(ctx context.Context) (*relayconn.ListenResult, error) {
				return relayconn.ListenRelayTCP(ctx, tcpAddr)
			},
			dial: func(ctx context.Context, token []byte) (*relayconn.RelayConn, error) {
				return relayconn.DialRelayTCP(ctx, tcpAddr, token)
			},
		},
		"tls": {
			listen: func(ctx context.Context) (*relayconn.ListenResult, error) {
				return relayconn.ListenRelayTLS(ctx, tlsAddr, clientTLS)
			},
			dial: func(ctx context.Context, token []byte) (*relayconn.RelayConn, error) {
				return relayconn.DialRelayTLS(ctx, tlsAddr, token, clientTLS)
			},
		},
		"ws": {
			listen: func(ctx context.Context) (*relayconn.ListenResult, error) {
				return relayconn.ListenRelay(ctx, wsAddr)
			},
			dial: func(ctx context.Context, token []byte) (*relayconn.RelayConn, error) {
				return relayconn.DialRelay(ctx, wsAddr, token)
			},
		},
	}
}

// frameRecorder is a RelayConn that records the size of the largest
// frame kamune writes to it.
type frameRecorder struct {
	*relayconn.RelayConn
	mu      sync.Mutex
	largest int
}

func (r *frameRecorder) WriteBytes(data []byte) error {
	r.mu.Lock()
	r.largest = max(r.largest, len(data))
	r.mu.Unlock()
	return r.RelayConn.WriteBytes(data)
}

func (r *frameRecorder) Largest() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.largest
}

// openTestStorage opens an unencrypted kamune store in a temporary
// directory, closed when t ends.
func openTestStorage(t *testing.T) *storage.Storage {
	t.Helper()
	s, err := storage.OpenStorage(
		storage.WithDBPath(filepath.Join(t.TempDir(), "kamune.db")),
		storage.WithNoPassphrase(),
	)
	require.New(t).NoError(err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestRelayCarriesLargestKamuneFrame runs a kamune session between two
// peers through the relay over tcp, tls and ws and has the listening peer
// echo messages that fill every padding bucket. The largest are padded to
// the top bucket, a frame of largestKamuneFrame bytes, which the relay
// must carry after its own wrapping without ending the session (RC-02).
func TestRelayCarriesLargestKamuneFrame(t *testing.T) {
	sizes := []int{
		1, 100, 900, 3000, 10_000, 30_000, 40_000, 60_000, 60_000, 60_000, 10,
	}
	verify := func(s *storage.Storage, p *storage.Peer) error {
		return s.StorePeer(p)
	}
	echo := func(tr *kamune.Transport) error {
		for {
			msg := kamune.Bytes(nil)
			if _, err := tr.Receive(msg); err != nil {
				return err
			}
			_, err := tr.Send(msg, kamune.RouteExchangeMessages)
			if err != nil {
				return err
			}
		}
	}

	endpoints := startTestRelay(t)
	for _, name := range []string{"tcp", "tls", "ws"} {
		t.Run(name, func(t *testing.T) {
			a := require.New(t)
			ep := endpoints[name]
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()

			res, err := ep.listen(ctx)
			a.NoError(err)
			srv, err := kamune.NewServer(
				"", echo, openTestStorage(t), verify,
				kamune.ServeWithListener(res.Listener),
			)
			a.NoError(err)
			served := make(chan struct{})
			go func() {
				defer close(served)
				_ = srv.ListenAndServe()
			}()
			t.Cleanup(func() {
				_ = srv.Close()
				<-served
			})

			var conn *frameRecorder
			dialer, err := kamune.NewDialer(
				name, openTestStorage(t), verify,
				kamune.DialWithFunc(func(string) (kamune.Conn, error) {
					rc, err := ep.dial(ctx, res.Token)
					if err != nil {
						return nil, err
					}
					conn = &frameRecorder{RelayConn: rc}
					return conn, nil
				}),
			)
			a.NoError(err)
			tr, err := dialer.Dial()
			a.NoError(err)
			defer tr.Close()

			for i, size := range sizes {
				payload := make([]byte, size)
				_, _ = rand.Read(payload)
				_, err := tr.Send(
					kamune.Bytes(payload), kamune.RouteExchangeMessages,
				)
				a.NoError(err, "send %d (%d bytes)", i, size)
				got := kamune.Bytes(nil)
				_, err = tr.Receive(got)
				a.NoError(err, "echo %d (%d bytes)", i, size)
				a.Equal(payload, got.GetValue(), "echo %d", i)
			}
			a.Equal(
				largestKamuneFrame, conn.Largest(),
				"the largest messages must use the top padding bucket",
			)
		})
	}
}
