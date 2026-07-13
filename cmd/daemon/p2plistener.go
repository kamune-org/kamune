package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/kamune-org/kamune"
	relaybroker "github.com/kamune-org/kamune/pkg/relayconn/broker"
	"github.com/xtaci/kcp-go/v5"
)

type p2pListener struct {
	bindAddr   string
	broker     *BrokerClient
	brokerAddr string
	token      []byte

	conn *net.UDPConn
	kcp  *kcp.Listener

	ctx        context.Context
	cancel     context.CancelFunc
	closeOnce  sync.Once
	closeErr   error
}

func newP2PListener(
	broker *BrokerClient, brokerAddr string, token []byte, bindAddr string,
) (*p2pListener, error) {
	if broker == nil {
		return nil, fmt.Errorf("broker is required")
	}
	if bindAddr == "" {
		bindAddr = ":0"
	}
	udpAddr, err := net.ResolveUDPAddr("udp4", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve bind addr: %w", err)
	}
	conn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("bind punch socket: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	l := &p2pListener{
		bindAddr:   bindAddr,
		broker:     broker,
		brokerAddr: brokerAddr,
		token:      token,
		conn:       conn,
		ctx:        ctx,
		cancel:     cancel,
	}

	brokerUDPAddr, err := net.ResolveUDPAddr("udp4", brokerAddr)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("resolve broker: %w", err)
	}
	claimIP, claimPort, err := broker.echoFrom(ctx, conn, brokerUDPAddr)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("broker echo: %w", err)
	}

	client, err := broker.Client(brokerAddr)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("broker client: %w", err)
	}
	pkt := relaybroker.BuildRegister(
		token, client.PublicKey(), claimIP, claimPort,
	)
	if _, err := conn.WriteToUDP(pkt, brokerUDPAddr); err != nil {
		l.Close()
		return nil, fmt.Errorf("send register: %w", err)
	}

	if len(token) == 0 {
		to, cancel := context.WithTimeout(ctx, 2*time.Second)
		assigned, err := readTokenAssigned(to, conn, broker, brokerUDPAddr)
		cancel()
		if err != nil {
			l.Close()
			return nil, fmt.Errorf("read assigned token: %w", err)
		}
		l.token = assigned
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		l.Close()
		return nil, fmt.Errorf("reset punch socket deadline: %w", err)
	}

	kcpL, err := kcp.ServeConn(nil, 0, 0, conn)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("kcp listener: %w", err)
	}
	l.kcp = kcpL

	go l.refreshLoop()

	return l, nil
}

func (l *p2pListener) Accept() (kamune.Conn, error) {
	sess, err := l.kcp.AcceptKCP()
	if err != nil {
		return nil, err
	}
	return kamune.NewConn(sess), nil
}

func (l *p2pListener) Close() error {
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

func (l *p2pListener) Token() string {
	if len(l.token) == 0 {
		return ""
	}
	return hex.EncodeToString(l.token)
}

func (l *p2pListener) Addr() *net.UDPAddr {
	if l.conn == nil {
		return nil
	}
	if addr, ok := l.conn.LocalAddr().(*net.UDPAddr); ok {
		return addr
	}
	return nil
}

func (l *p2pListener) refreshLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-l.ctx.Done():
			return
		case <-ticker.C:
			_ = l.refreshRegistration()
		}
	}
}

func (l *p2pListener) refreshRegistration() error {
	brokerUDPAddr, err := net.ResolveUDPAddr("udp4", l.brokerAddr)
	if err != nil {
		return fmt.Errorf("resolve broker: %w", err)
	}
	claimIP, claimPort, err := l.broker.echoSeparate(l.ctx, l.brokerAddr)
	if err != nil {
		return fmt.Errorf("broker echo: %w", err)
	}
	client, err := l.broker.Client(l.brokerAddr)
	if err != nil {
		return fmt.Errorf("broker client: %w", err)
	}
	pkt := relaybroker.BuildRegister(
		l.token, client.PublicKey(), claimIP, claimPort,
	)
	if _, err := l.conn.WriteToUDP(pkt, brokerUDPAddr); err != nil {
		return fmt.Errorf("send register: %w", err)
	}
	return nil
}

func readTokenAssigned(
	ctx context.Context, conn *net.UDPConn,
	broker *BrokerClient, brokerAddr *net.UDPAddr,
) ([]byte, error) {
	buf := make([]byte, 1500)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			return nil, fmt.Errorf("set deadline: %w", err)
		}
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return nil, fmt.Errorf("read notify: %w", err)
		}
		if src.IP.Equal(brokerAddr.IP) && src.Port == brokerAddr.Port {
			payload, err := broker.parseNotify(buf[:n])
			if err != nil {
				continue
			}
			if payload.Type == relaybroker.NotifyTokenAssigned {
				return payload.Token, nil
			}
		}
	}
}
