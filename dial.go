package kamune

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/hossein1376/kamune/pkg/attest"
)

type dialer struct {
	conn           Conn
	verifyRemote   RemoteVerifier
	connOverridden bool
}

func Dial(addr string, opts ...DialOption) (*Transport, error) {
	d := &dialer{}
	for _, opt := range opts {
		if err := opt(d); err != nil {
			return nil, fmt.Errorf("applying options: %w", err)
		}
	}

	if d.verifyRemote == nil {
		d.verifyRemote = defaultRemoteVerifier
	}
	if !d.connOverridden {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("dialing address: %w", err)
		}
		d.conn, _ = newTCPConn(conn)
	}

	transport, err := d.handshake()
	if err != nil {
		return nil, fmt.Errorf("handshake: %w", err)
	}

	return transport, err
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

func DialWithExistingConn(conn Conn) DialOption {
	return func(d *dialer) error {
		if d.connOverridden {
			return errors.New("already have a conn override")
		}
		d.conn = conn
		d.connOverridden = true
		return nil
	}
}
