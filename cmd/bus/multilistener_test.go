package main

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune"
)

// closingListener is a listener whose Accept blocks until it is closed.
type closingListener struct {
	once   sync.Once
	closed chan struct{}
}

func newClosingListener() *closingListener {
	return &closingListener{closed: make(chan struct{})}
}

func (l *closingListener) Accept() (kamune.Conn, error) {
	<-l.closed
	return nil, net.ErrClosed
}

func (l *closingListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *closingListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

func (l *closingListener) isClosed() bool {
	select {
	case <-l.closed:
		return true
	default:
		return false
	}
}

// TestMultiListenerAddRacesClose checks that a listener added while the
// multiListener closes is either refused or closed with it, and that
// concurrent Close calls neither panic nor both succeed.
func TestMultiListenerAddRacesClose(t *testing.T) {
	a := require.New(t)
	const (
		rounds  = 2000
		adders  = 4
		closers = 2
	)
	for range rounds {
		ml := newMultiListener()
		listeners := make([]*closingListener, adders)
		added := make([]bool, adders)
		closeErrs := make([]error, closers)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range adders {
			listeners[i] = newClosingListener()
			wg.Go(func() {
				<-start
				added[i] = ml.Add(listeners[i]) == nil
			})
		}
		for i := range closers {
			wg.Go(func() {
				<-start
				closeErrs[i] = ml.Close()
			})
		}
		close(start)
		finished := make(chan struct{})
		go func() {
			wg.Wait()
			close(finished)
		}()
		select {
		case <-finished:
		case <-time.After(testWait):
			t.Fatal("Add or Close did not return")
		}

		succeeded := 0
		for _, err := range closeErrs {
			if err == nil {
				succeeded++
			} else {
				a.ErrorIs(err, net.ErrClosed)
			}
		}
		a.Equal(1, succeeded, "exactly one Close must close the listener")
		for i, l := range listeners {
			if added[i] {
				a.True(l.isClosed(),
					"a listener added before Close must be closed by it")
			} else {
				a.False(l.isClosed())
			}
		}
	}
}
