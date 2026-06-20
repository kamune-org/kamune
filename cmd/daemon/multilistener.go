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
}

func newMultiListener() *multiListener {
	return &multiListener{
		connCh: make(chan kamune.Conn),
		done:   make(chan struct{}),
	}
}

func (m *multiListener) Add(l kamune.Listener) error {
	select {
	case <-m.done:
		return net.ErrClosed
	default:
	}

	m.mu.Lock()
	m.listeners = append(m.listeners, l)
	m.mu.Unlock()

	m.wg.Add(1)
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
	select {
	case <-m.done:
		return net.ErrClosed
	default:
		close(m.done)
	}

	m.mu.Lock()
	for _, l := range m.listeners {
		l.Close()
	}
	m.mu.Unlock()

	m.wg.Wait()
	return nil
}
