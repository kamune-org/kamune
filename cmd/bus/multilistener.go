package main

import (
	"net"
	"sync"

	"github.com/kamune-org/kamune"
)

// multiListener hands a kamune server the connections of every listener
// added to it. Close closes it and every listener added before, and an
// Add after Close fails, so no listener outlives it.
type multiListener struct {
	mu        sync.Mutex
	listeners []kamune.Listener
	connCh    chan kamune.Conn
	done      chan struct{}
	wg        sync.WaitGroup
	// closed is set by the first Close. Add and Close read and set it
	// under mu, so that a listener is either added before Close, which
	// then closes it, or refused.
	closed bool
}

func newMultiListener() *multiListener {
	return &multiListener{
		connCh: make(chan kamune.Conn),
		done:   make(chan struct{}),
	}
}

// Add starts handing over the connections of l. It returns net.ErrClosed
// once m is closed; the caller still owns l then.
func (m *multiListener) Add(l kamune.Listener) error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return net.ErrClosed
	}
	m.listeners = append(m.listeners, l)
	m.wg.Add(1)
	m.mu.Unlock()

	go func() {
		defer m.wg.Done()
		for {
			cn, err := l.Accept()
			if err != nil {
				return
			}
			select {
			case m.connCh <- cn:
			case <-m.done:
				cn.Close()
				return
			}
		}
	}()
	return nil
}

// Done is closed once the listener is closed.
func (m *multiListener) Done() <-chan struct{} { return m.done }

func (m *multiListener) Accept() (kamune.Conn, error) {
	select {
	case cn := <-m.connCh:
		return cn, nil
	case <-m.done:
		return nil, net.ErrClosed
	}
}

// Close closes m and every listener added to it, and waits for their
// accept loops to end. Only the first call does so; later calls return
// net.ErrClosed.
func (m *multiListener) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return net.ErrClosed
	}
	m.closed = true
	close(m.done)
	listeners := append([]kamune.Listener(nil), m.listeners...)
	m.mu.Unlock()

	for _, l := range listeners {
		_ = l.Close()
	}
	m.wg.Wait()
	return nil
}
