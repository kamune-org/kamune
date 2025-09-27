package kamune

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"
	"time"

	"github.com/xtaci/kcp-go/v5"

	"github.com/kamune-org/kamune/pkg/attest"
)

type dialer struct {
	conn         *Conn
	storage      *Storage
	attester     attest.Attester
	connType     connType
	verifyRemote RemoteVerifier
	readTimeout  time.Duration
	writeTimeout time.Duration
	dialTimeout  time.Duration
	connOpts     []ConnOption
	storageOpts  []StorageOption
}

func Dial(addr string, opts ...DialOption) (*Transport, error) {
	d := &dialer{
		connType:     tcp,
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

	storage, err := openStorage(d.storageOpts...)
	if err != nil {
		return nil, fmt.Errorf("opening storage: %w", err)
	}
	at, err := storage.attester()
	if err != nil {
		return nil, fmt.Errorf("loading attester: %w", err)
	}
	d.storage = storage
	d.attester = at

	transport, err := d.handshake()
	if err != nil {
		return nil, fmt.Errorf("handshake: %w", err)
	}

	return transport, err
}

func (d dialer) dial(addr string) (*Conn, error) {
	switch d.connType {
	case tcp:
		c, err := net.Dial("tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("dialing tcp: %w", err)
		}
		conn, err := newConn(c, d.connOpts...)
		if err != nil {
			return nil, fmt.Errorf("new tcp conn: %w", err)
		}
		return conn, nil
	case udp:
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
		if msg := recover(); msg != nil {
			slog.Error(
				"dial panic",
				slog.Any("message", msg),
				slog.String("stack", string(debug.Stack())),
			)
		}
	}()

	if err := sendIntroduction(d.conn, d.attester); err != nil {
		return nil, fmt.Errorf("send introduction: %w", err)
	}
	remote, err := receiveIntroduction(d.conn, d.storage.identity)
	if err != nil {
		return nil, fmt.Errorf("receive introduction: %w", err)
	}
	if err = d.verifyRemote(d.storage, remote); err != nil {
		return nil, fmt.Errorf("verify remote: %w", err)
	}

	pt := newPlainTransport(d.conn, remote, d.attester, d.storage.identity)
	t, err := requestHandshake(pt, d.storage)
	if err != nil {
		return nil, fmt.Errorf("request handshake: %w", err)
	}

	return t, nil
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
		d.connType = tcp
		d.connOpts = opts
		return nil
	}
}

func DialWithUDPConn(opts ...ConnOption) DialOption {
	return func(d *dialer) error {
		d.connType = udp
		d.connOpts = opts
		return nil
	}
}

func DialWithStorageOpts(opts ...StorageOption) DialOption {
	return func(d *dialer) error {
		d.storageOpts = opts
		return nil
	}
}
