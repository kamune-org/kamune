package main

import (
	"net"
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
	return nil
}
