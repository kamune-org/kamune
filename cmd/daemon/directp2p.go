package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/kamune-org/kamune"
	"github.com/xtaci/kcp-go/v5"
)

type directP2PListener struct {
	conn     *net.UDPConn
	kcp      *kcp.Listener
	peerAddr *net.UDPAddr
	ctx      context.Context
	cancel   context.CancelFunc
	closeOnce sync.Once
	closeErr  error
}

func newDirectP2PListener(listenAddr, peerAddr string) (*directP2PListener, error) {
	udpAddr, err := net.ResolveUDPAddr("udp4", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve listen addr: %w", err)
	}
	conn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("bind punch socket: %w", err)
	}

	peerUDPAddr, err := net.ResolveUDPAddr("udp4", peerAddr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("resolve peer addr: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	l := &directP2PListener{
		conn:     conn,
		peerAddr: peerUDPAddr,
		ctx:      ctx,
		cancel:   cancel,
	}

	kcpL, err := kcp.ServeConn(nil, 0, 0, conn)
	if err != nil {
		conn.Close()
		cancel()
		return nil, fmt.Errorf("kcp listener: %w", err)
	}
	l.kcp = kcpL

	go l.natKickLoop()

	return l, nil
}

func (l *directP2PListener) natKickLoop() {
	timeout := time.After(10 * time.Second)
	for {
		sendNATKick(l.ctx, l.conn, l.peerAddr)
		select {
		case <-l.ctx.Done():
			return
		case <-timeout:
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func (l *directP2PListener) Accept() (kamune.Conn, error) {
	sess, err := l.kcp.AcceptKCP()
	if err != nil {
		return nil, err
	}
	return kamune.NewConn(sess), nil
}

func (l *directP2PListener) Close() error {
	l.closeOnce.Do(func() {
		l.cancel()
		if l.kcp != nil {
			_ = l.kcp.Close()
		}
		if l.conn != nil {
			l.closeErr = l.conn.Close()
		}
	})
	return l.closeErr
}

func (l *directP2PListener) Addr() *net.UDPAddr {
	if l.conn == nil {
		return nil
	}
	if addr, ok := l.conn.LocalAddr().(*net.UDPAddr); ok {
		return addr
	}
	return nil
}

func directP2PDial(peerAddr string) (kamune.Conn, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("bind punch socket: %w", err)
	}

	peerUDPAddr, err := net.ResolveUDPAddr("udp4", peerAddr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("resolve peer addr: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sendNATKick(ctx, conn, peerUDPAddr)

	var convid uint32
	binary.Read(rand.Reader, binary.LittleEndian, &convid)
	sess, err := kcp.NewConn4(convid, peerUDPAddr, nil, 0, 0, true, conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("kcp session: %w", err)
	}
	return kamune.NewConn(sess), nil
}
