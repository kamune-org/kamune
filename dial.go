package kamune

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/xtaci/kcp-go/v5"

	"github.com/hossein1376/kamune/pkg/attest"
)

type dialer struct {
	conn         *Conn
	connType     ConnType
	connOpts     []ConnOption
	verifyRemote RemoteVerifier
	readTimeout  time.Duration
	writeTimeout time.Duration
	dialTimeout  time.Duration
}

func Dial(addr string, opts ...DialOption) (*Transport, error) {
	d := &dialer{
		connType:     TCP,
		readTimeout:  10 * time.Minute,
		writeTimeout: 1 * time.Minute,
		dialTimeout:  10 * time.Second,
		verifyRemote: defaultRemoteVerifier,
	}
	for _, opt := range opts {
		if err := opt(d); err != nil {
			return nil, fmt.Errorf("applying options: %w", err)
		}
	}

	if d.conn == nil {
		c, err := d.dial(addr)
		if err != nil {
			return nil, fmt.Errorf("dialing: %w", err)
		}
		d.conn = c
	}

	transport, err := d.handshake()
	if err != nil {
		return nil, fmt.Errorf("handshake: %w", err)
	}

	return transport, err
}

func (d dialer) dial(addr string) (*Conn, error) {
	switch d.connType {
	case TCP:
		c, err := net.Dial("tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("dialing tcp: %w", err)
		}
		conn, err := newConn(c, d.connOpts...)
		if err != nil {
			return nil, fmt.Errorf("new tcp conn: %w", err)
		}
		return conn, nil
	case UDP:
		c, err := kcp.Dial(addr)
		if err != nil {
			return nil, fmt.Errorf("dialing udp: %w", err)
		}
		conn, err := newConn(c, d.connOpts...)
		if err != nil {
			return nil, fmt.Errorf("new udp conn: %w", err)
		}
		return conn, nil
	default:
		panic("unknown connection type")
	}
}

func (d *dialer) handshake() (*Transport, error) {
	defer func() {
		if err := recover(); err != nil {
			d.log(slog.LevelError, "dial panic", slog.Any("err", err))
		}
	}()
	at, err := attest.LoadFromDisk(privKeyPath)
	if err != nil {
		return nil, fmt.Errorf("loading certificate: %w", err)
	}

	if err = sendIntroduction(d.conn, at); err != nil {
		return nil, fmt.Errorf("send introduction: %w", err)
	}
	remote, err := receiveIntroduction(d.conn)
	if err != nil {
		return nil, fmt.Errorf("receive introduction: %w", err)
	}
	if err = d.verifyRemote(remote); err != nil {
		return nil, fmt.Errorf("verify remote: %w", err)
	}

	pt := &plainTransport{conn: d.conn, attest: at, remote: remote}
	t, err := requestHandshake(pt)
	if err != nil {
		return nil, fmt.Errorf("request handshake: %w", err)
	}

	return t, nil
}

func (dialer) log(lvl slog.Level, msg string, args ...any) {
	slog.Log(context.Background(), lvl, msg, args...)
}

type DialOption func(*dialer) error

func DialWithRemoteVerifier(verifier RemoteVerifier) DialOption {
	return func(d *dialer) error {
		if d.verifyRemote != nil {
			return errors.New("already have a remote verifier")
		}
		d.verifyRemote = verifier
		return nil
	}
}

func DialWithExistingConn(conn *Conn) DialOption {
	return func(d *dialer) error {
		if d.conn != nil {
			return errors.New("already have a conn override")
		}
		d.conn = conn
		return nil
	}
}

func DialWithReadTimeout(timeout time.Duration) DialOption {
	return func(d *dialer) error {
		d.readTimeout = timeout
		return nil
	}
}

func DialWithWriteTimeout(timeout time.Duration) DialOption {
	return func(d *dialer) error {
		d.writeTimeout = timeout
		return nil
	}
}

func DialWithDialTimeout(timeout time.Duration) DialOption {
	return func(d *dialer) error {
		d.dialTimeout = timeout
		return nil
	}
}

func DialWithTCPConn(opts ...ConnOption) DialOption {
	return func(d *dialer) error {
		d.connType = TCP
		d.connOpts = opts
		return nil
	}
}

func DialWithUDPConn(opts ...ConnOption) DialOption {
	return func(d *dialer) error {
		d.connType = UDP
		d.connOpts = opts
		return nil
	}
}
