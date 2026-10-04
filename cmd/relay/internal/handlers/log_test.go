package handlers

import (
	"bytes"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/relayconn/pb"
)

// syncBuffer is a bytes.Buffer safe for a slog handler shared by
// goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureLog sends the default logger's records at level and above to the
// returned buffer until t ends.
func captureLog(t *testing.T, level slog.Level) *syncBuffer {
	t.Helper()
	out := &syncBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(
		out, &slog.HandlerOptions{Level: level},
	)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return out
}

// TestHandleRelayConn_KeepsAddressesOutOfInfoLog checks that pairing two
// peers, or a malformed join, logs no client address at the default info
// level: a listener's line next to its dialer's would record who talked
// to whom. The registrations are still logged at debug.
func TestHandleRelayConn_KeepsAddressesOutOfInfoLog(t *testing.T) {
	const (
		listenerIP = "198.51.100.7"
		dialerIP   = "203.0.113.9"
		badIP      = "192.0.2.5"
	)
	tests := []struct {
		name  string
		level slog.Level
		debug bool
	}{
		{name: "info", level: slog.LevelInfo},
		{name: "debug", level: slog.LevelDebug, debug: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			out := captureLog(t, tc.level)
			hub := newTestHub(t, "", 0)

			serve := func(ip string) (net.Conn, <-chan struct{}) {
				client, server := net.Pipe()
				done := make(chan struct{})
				go func() {
					defer close(done)
					handleRelayConn(
						hub, newRawTCPAdapter(server, 0),
						net.JoinHostPort(ip, "40123"), nil,
					)
				}()
				t.Cleanup(func() { _ = client.Close() })
				return client, done
			}
			wait := func(done <-chan struct{}) {
				select {
				case <-done:
				case <-time.After(10 * time.Second):
					a.FailNow("handler did not return")
				}
			}

			lc, lDone := serve(listenerIP)
			_, reg := dialClient(
				t, lc, "", "", pb.Register_MODE_CREATE, nil,
			)
			dc, dDone := serve(dialerIP)
			dialClient(t, dc, "", "", pb.Register_MODE_JOIN, reg.GetToken())

			bc, bDone := serve(badIP)
			bch, err := exchange.Initiate(newRawTCPAdapter(bc, 0))
			a.NoError(err)
			sendFrame(t, bch, &pb.Frame{
				Kind: &pb.Frame_Register{Register: &pb.Register{
					Mode: pb.Register_MODE_JOIN,
				}},
			})
			wait(bDone)

			a.NoError(lc.Close())
			a.NoError(dc.Close())
			wait(lDone)
			wait(dDone)

			got := out.String()
			if tc.debug {
				a.Contains(got, "peer registered")
				a.Contains(got, listenerIP)
				a.Contains(got, dialerIP)
				return
			}
			a.NotContains(got, "peer registered")
			for _, ip := range []string{listenerIP, dialerIP, badIP} {
				a.NotContains(got, ip)
			}
		})
	}
}
