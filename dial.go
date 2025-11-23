package kamune

import (
	"crypto/sha1"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"
	"time"

	"github.com/xtaci/kcp-go/v5"

	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/pkg/fingerprint"
)

type Dialer struct {
	address      string
	conn         Conn
	storage      *Storage
	attester     attest.Attester
	algorithm    attest.Algorithm
	clientName   string
	connType     connType
	verifyRemote RemoteVerifier
	readTimeout  time.Duration
	writeTimeout time.Duration
	dialTimeout  time.Duration
	connOpts     []ConnOption
	storageOpts  []StorageOption
}

func (d *Dialer) Dial() (*Transport, error) {
	if d.conn == nil {
		c, err := d.dial(d.address)
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

func (d *Dialer) dial(addr string) (*conn, error) {
	switch d.connType {
	case tcp:
		c, err := net.Dial("tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("dialing tcp: %w", err)
		}
		cn, err := newConn(c, d.connOpts...)
		if err != nil {
			return nil, fmt.Errorf("new tcp conn: %w", err)
		}
		return cn, nil
	case udp:
		c, err := kcp.Dial(addr)
		if err != nil {
			return nil, fmt.Errorf("dialing udp: %w", err)
		}
		cn, err := newConn(c, d.connOpts...)
		if err != nil {
			return nil, fmt.Errorf("new udp conn: %w", err)
		}
		return cn, nil
	default:
		panic(fmt.Errorf("unknown connection type: %v", d.connType))
	}
}

func (d *Dialer) handshake() (*Transport, error) {
	defer func() {
		if msg := recover(); msg != nil {
			slog.Error(
				"dial panic",
				slog.Any("message", msg),
				slog.String("stack", string(debug.Stack())),
			)
		}
	}()

	err := sendIntroduction(d.conn, d.clientName, d.attester, d.algorithm)
	if err != nil {
		return nil, fmt.Errorf("send introduction: %w", err)
	}
	st, err := readSignedTransport(d.conn)
	if err != nil {
		return nil, fmt.Errorf("read transport: %w", err)
	}
	peer, err := receiveIntroduction(st)
	if err != nil {
		return nil, fmt.Errorf("receive introduction: %w", err)
	}
	err = d.verifyRemote(d.storage, peer)
	if err != nil {
		return nil, fmt.Errorf("verify remote: %w", err)
	}

	pt := newPlainTransport(d.conn, peer.PublicKey, d.attester, d.storage)
	t, err := requestHandshake(pt)
	if err != nil {
		return nil, fmt.Errorf("request handshake: %w", err)
	}

	return t, nil
}

func (d *Dialer) PublicKey() PublicKey {
	return d.attester.PublicKey()
}

func NewDialer(addr string, opts ...DialOption) (*Dialer, error) {
	d := &Dialer{
		address:      addr,
		connType:     tcp,
		algorithm:    attest.Ed25519Algorithm,
		readTimeout:  5 * time.Minute,
		writeTimeout: 1 * time.Minute,
		dialTimeout:  10 * time.Second,
		verifyRemote: defaultRemoteVerifier,
	}
	for _, opt := range opts {
		if err := opt(d); err != nil {
			return nil, fmt.Errorf("applying options: %w", err)
		}
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
	sum := sha1.Sum((at.PublicKey().Marshal()))
	d.clientName = fingerprint.Base64(sum[:])

	return d, nil
}

type DialOption func(*Dialer) error

func DialWithRemoteVerifier(verifier RemoteVerifier) DialOption {
	return func(d *Dialer) error {
		if d.verifyRemote != nil {
			return errors.New("already have a remote verifier")
		}
		d.verifyRemote = verifier
		return nil
	}
}

func DialWithExistingConn(conn Conn) DialOption {
	return func(d *Dialer) error {
		if d.conn != nil {
			return errors.New("already have a conn override")
		}
		d.conn = conn
		return nil
	}
}

func DialWithReadTimeout(timeout time.Duration) DialOption {
	return func(d *Dialer) error {
		d.readTimeout = timeout
		return nil
	}
}

func DialWithWriteTimeout(timeout time.Duration) DialOption {
	return func(d *Dialer) error {
		d.writeTimeout = timeout
		return nil
	}
}

func DialWithDialTimeout(timeout time.Duration) DialOption {
	return func(d *Dialer) error {
		d.dialTimeout = timeout
		return nil
	}
}

func DialWithTCPConn(opts ...ConnOption) DialOption {
	return func(d *Dialer) error {
		d.connType = tcp
		d.connOpts = opts
		return nil
	}
}

func DialWithUDPConn(opts ...ConnOption) DialOption {
	return func(d *Dialer) error {
		d.connType = udp
		d.connOpts = opts
		return nil
	}
}

func DialWithAlgorithm(a attest.Algorithm) DialOption {
	return func(d *Dialer) error {
		d.algorithm = a
		return nil
	}
}

func DialWithClientName(name string) DialOption {
	return func(d *Dialer) error {
		d.clientName = name
		return nil
	}
}

func DialWithStorageOpts(opts ...StorageOption) DialOption {
	return func(d *Dialer) error {
		d.storageOpts = opts
		return nil
	}
}
