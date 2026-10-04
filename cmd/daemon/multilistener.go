package main

import (
	"net"
	"slices"
	"sync"

	"github.com/kamune-org/kamune"
)

type multiListener struct {
	mu        sync.Mutex
	listeners []kamune.Listener
	connCh    chan kamune.Conn
	done      chan struct{}
	wg        sync.WaitGroup
	closed    bool
}

func newMultiListener() *multiListener {
	return &multiListener{
		connCh: make(chan kamune.Conn),
		done:   make(chan struct{}),
	}
}

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
				m.remove(l)
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

// remove forgets l, whose Accept has failed for good.
func (m *multiListener) remove(l kamune.Listener) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listeners = slices.DeleteFunc(m.listeners, func(x kamune.Listener) bool {
		return x == l
	})
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
	for {
		select {
		case cn := <-m.connCh:
			if cn != nil {
				_ = cn.Close()
			}
		default:
			return nil
		}
	}
}
