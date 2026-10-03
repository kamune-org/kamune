package services

import (
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/relayconn/pb"
	"github.com/stretchr/testify/require"
)

type failWriteAdapter struct {
	inner interface {
		ReadBytes() ([]byte, error)
		WriteBytes([]byte) error
		Close() error
	}
	fail   atomic.Bool
	closed atomic.Bool
}

func (f *failWriteAdapter) ReadBytes() ([]byte, error) {
	return f.inner.ReadBytes()
}

func (f *failWriteAdapter) WriteBytes(data []byte) error {
	if f.fail.Load() {
		return io.ErrClosedPipe
	}
	return f.inner.WriteBytes(data)
}

func (f *failWriteAdapter) Close() error {
	f.closed.Store(true)
	return f.inner.Close()
}

func TestHandlePing_WriteErrorClosesChannel(t *testing.T) {
	a := require.New(t)
	left, right := net.Pipe()
	t.Cleanup(func() {
		_ = left.Close()
		_ = right.Close()
	})

	listenerAdapter := &failWriteAdapter{inner: &testAdapter{conn: left}}
	acceptErr := make(chan error, 1)
	var peer *exchange.Channel
	go func() {
		ch, err := exchange.Accept(&testAdapter{conn: right})
		peer = ch
		acceptErr <- err
	}()
	listener, err := exchange.Initiate(listenerAdapter)
	a.NoError(err)
	a.NoError(<-acceptErr)

	listenerAdapter.fail.Store(true)

	sm := newTestSessionManager(time.Minute, 0, 10)
	hub := NewHub(sm, "", 0, nil, 0)
	token, err := sm.Create(listener)
	a.NoError(err)

	done := make(chan struct{})
	go func() {
		hub.ReadPump(listener, token)
		close(done)
	}()

	sendFrame(t, peer, &pb.Frame{Kind: &pb.Frame_Ping{Ping: &pb.Ping{}}})

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("read pump did not exit after a failed pong")
	}
	a.True(listenerAdapter.closed.Load())
}
