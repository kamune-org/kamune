package relayconn

import (
	"encoding/binary"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/relayconn/pb"
)

// channelPair returns the two ends of an HPKE channel over net.Pipe.
// The first is the client end, the second the relay end.
func channelPair(t *testing.T) (*exchange.Channel, *exchange.Channel) {
	t.Helper()
	a := require.New(t)
	c, s := net.Pipe()
	t.Cleanup(func() { c.Close(); s.Close() })

	type result struct {
		ch  *exchange.Channel
		err error
	}
	server := make(chan result, 1)
	go func() {
		ch, err := exchange.Accept(newTCPAdapter(s))
		server <- result{ch, err}
	}()
	clientCh, err := exchange.Initiate(newTCPAdapter(c))
	a.NoError(err)
	res := <-server
	a.NoError(res.err)
	return clientCh, res.ch
}

func msgFrame(data []byte) []byte {
	b, _ := proto.Marshal(&pb.Frame{
		Kind: &pb.Frame_Msg{Msg: &pb.Message{Data: data}},
	})
	return b
}

func (rc *RelayConn) buffered() (frames, size int) {
	rc.bufMu.Lock()
	defer rc.bufMu.Unlock()
	return len(rc.buf), rc.bufBytes
}

// TestRelayConnReceiveBufferBounded floods a RelayConn that nobody
// reads and checks that the buffer stops at its caps, that the sender
// is pushed back, and that draining delivers every frame in order.
func TestRelayConnReceiveBufferBounded(t *testing.T) {
	tests := []struct {
		name       string
		frameSize  int
		wantFrames int
	}{
		{"frame cap", 8, maxBufferedFrames},
		{"byte cap", 60000, maxBufferedBytes / 60000},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			clientCh, serverCh := channelPair(t)

			var mu sync.Mutex
			rc := newRelayConn(t.Context(), clientCh, &mu)
			rc.closeFn = func() { clientCh.Close() }
			t.Cleanup(func() { rc.Close() })
			go rc.readPump()

			total := tc.wantFrames + 20
			var sent atomic.Int64
			go func() {
				for i := range total {
					data := make([]byte, tc.frameSize)
					binary.BigEndian.PutUint32(data, uint32(i))
					if serverCh.WriteBytes(msgFrame(data)) != nil {
						return
					}
					sent.Add(1)
				}
			}()

			a.Eventually(func() bool {
				n, _ := rc.buffered()
				return n == tc.wantFrames
			}, 10*time.Second, 5*time.Millisecond)
			time.Sleep(100 * time.Millisecond)

			n, size := rc.buffered()
			a.Equal(tc.wantFrames, n)
			a.LessOrEqual(size, maxBufferedBytes)
			a.Less(sent.Load(), int64(total))

			a.NoError(rc.SetDeadline(time.Now().Add(10 * time.Second)))
			for i := range total {
				got, err := rc.ReadBytes()
				a.NoError(err)
				a.Len(got, tc.frameSize)
				a.Equal(uint32(i), binary.BigEndian.Uint32(got))
			}
		})
	}
}

// TestRelayConnCloseWhileBufferFull checks that closing a connection
// whose reader is blocked on a full buffer returns promptly and stops
// the reader.
func TestRelayConnCloseWhileBufferFull(t *testing.T) {
	a := require.New(t)
	listener, serverCh := setupListener(t)

	go func() {
		for range maxBufferedFrames + 10 {
			if serverCh.WriteBytes(msgFrame([]byte("x"))) != nil {
				return
			}
		}
	}()

	conn, err := listener.Accept()
	a.NoError(err)
	rc := conn.(*RelayConn)
	a.Eventually(func() bool {
		n, _ := rc.buffered()
		return n == maxBufferedFrames
	}, 10*time.Second, 5*time.Millisecond)

	closed := make(chan struct{})
	go func() {
		conn.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		a.Fail("Close blocked while the receive buffer was full")
	}
}

// TestRelayConnSetDeadlineWakesReader changes the deadline while
// ReadBytes is blocked and checks that the read applies it at once, as
// a net.Conn read does.
func TestRelayConnSetDeadlineWakesReader(t *testing.T) {
	t.Run("expire", func(t *testing.T) {
		a := require.New(t)
		clientCh, _ := channelPair(t)
		var mu sync.Mutex
		rc := newRelayConn(t.Context(), clientCh, &mu)
		rc.closeFn = func() { clientCh.Close() }
		go rc.readPump()
		defer rc.Close()

		done := make(chan error, 1)
		go func() {
			_, err := rc.ReadBytes()
			done <- err
		}()
		time.Sleep(50 * time.Millisecond)
		a.NoError(rc.SetDeadline(time.Now()))

		select {
		case err := <-done:
			a.ErrorIs(err, os.ErrDeadlineExceeded)
		case <-time.After(2 * time.Second):
			a.Fail("blocked read ignored the new deadline")
		}
	})

	t.Run("clear", func(t *testing.T) {
		a := require.New(t)
		clientCh, relayCh := channelPair(t)
		var mu sync.Mutex
		rc := newRelayConn(t.Context(), clientCh, &mu)
		rc.closeFn = func() { clientCh.Close() }
		go rc.readPump()
		defer rc.Close()

		a.NoError(rc.SetDeadline(time.Now().Add(300 * time.Millisecond)))
		type result struct {
			err  error
			data []byte
		}
		done := make(chan result, 1)
		go func() {
			data, err := rc.ReadBytes()
			done <- result{data: data, err: err}
		}()
		time.Sleep(50 * time.Millisecond)
		a.NoError(rc.SetDeadline(time.Time{}))

		select {
		case res := <-done:
			a.Failf("read returned after its deadline was cleared",
				"data %q, err %v", res.data, res.err)
		case <-time.After(700 * time.Millisecond):
		}
		a.NoError(relayCh.WriteBytes(msgFrame([]byte("late"))))
		select {
		case res := <-done:
			a.NoError(res.err)
			a.Equal("late", string(res.data))
		case <-time.After(2 * time.Second):
			a.Fail("read did not return the frame")
		}
	})
}

// TestRelayConnPushAfterClose checks that a frame delivered to a
// connection that has already closed is dropped, not buffered.
func TestRelayConnPushAfterClose(t *testing.T) {
	a := require.New(t)
	rc := newRelayConn(t.Context(), nil, &sync.Mutex{})
	a.NoError(rc.Close())

	a.False(rc.pushData([]byte("late")))
	frames, size := rc.buffered()
	a.Zero(frames)
	a.Zero(size)
}
