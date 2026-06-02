package kamune

import (
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"
	"time"

	"github.com/xtaci/kcp-go/v5"

	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
)

// Dialer handles outgoing connections and initiates handshakes.
type Dialer struct {
	attest        *attest.Attest
	storage       *storage.Storage
	dialFunc      func(addr string) (Conn, error)
	clientName    string
	address       string
	handshakeOpts handshakeOpts
	connOpts      []ConnOption
	dialTimeout   time.Duration
}

// Dial establishes a connection and performs the handshake.
func (d *Dialer) Dial() (*Transport, error) {
	cn, err := d.dial(d.address)
	if err != nil {
		return nil, fmt.Errorf("dialing: %w", err)
	}

	transport, err := d.handshake(cn)
	if err != nil {
		cn.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}

	return transport, nil
}

func (d *Dialer) dial(addr string) (Conn, error) {
	if d.dialFunc != nil {
		return d.dialFunc(addr)
	}
	// defaults to TCP
	c, err := net.DialTimeout("tcp", addr, d.dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("dialing tcp: %w", err)
	}
	return newConn(c, d.connOpts...), nil
}

func (d *Dialer) handshake(cn Conn) (*Transport, error) {
	defer func() {
		if msg := recover(); msg != nil {
			slog.Error(
				"handshake dial panic",
				slog.Any("message", msg),
				slog.String("stack", string(debug.Stack())),
			)
		}
	}()

	// Bound the handshake to avoid indefinite blocking.
	_ = cn.SetDeadline(time.Now().Add(d.handshakeOpts.timeout))
	defer func() { _ = cn.SetDeadline(time.Time{}) }()

	// Step 0: Exchange HPKE keys to derive an encrypted connection for the
	// handshake
	ec, err := exchange.Initiate(cn)
	if err != nil {
		return nil, fmt.Errorf("initiate exchange: %w", err)
	}

	// Step 1: Send our introduction
	err = sendIntroduction(ec, d.attest, d.clientName, AppVersion)
	if err != nil {
		return nil, fmt.Errorf("send introduction: %w", err)
	}

	// Step 2: Receive peer's introduction
	st, err := readSignedTransport(ec)
	if err != nil {
		return nil, fmt.Errorf("read transport: %w", err)
	}

	// Validate route
	if r := RouteFromProto(st.GetMetadata().Route); r != RouteIdentity {
		return nil, fmt.Errorf(
			"%w: expected %s, got %s", ErrUnexpectedRoute, RouteIdentity, r,
		)
	}

	peer, remoteVersion, err := receiveIntroduction(st)
	if err != nil {
		return nil, fmt.Errorf("receive introduction: %w", err)
	}

	if err := checkVersion(remoteVersion); err != nil {
		return nil, fmt.Errorf("version check: %w", err)
	}

	if err := d.handshakeOpts.remoteVerifier(d.storage, peer); err != nil {
		return nil, fmt.Errorf("verify remote: %w", err)
	}
	serde := newSignedSerde(peer.PublicKey, d.attest)

	// Step 3: Proceed with the handshake
	t, err := requestHandshake(ec, serde, d.handshakeOpts)
	if err != nil {
		return nil, fmt.Errorf("request handshake: %w", err)
	}

	// Since from now on all communications are encrypted via the newly ciphers
	// derived from the handshake, we can switch to the plain connection.
	t.conn = cn
	t.remotePeer = peer

	slog.Info(
		"session established",
		slog.String("session_id", t.sessionID),
		slog.String("peer", peer.Name),
	)

	return t, nil
}

// PublicKey returns the dialer's public key.
func (d *Dialer) PublicKey() []byte {
	return d.attest.MarshalPublicKey()
}

// NewDialer creates a new dialer with the given address, storage, and options.
func NewDialer(
	addr string, store *storage.Storage, opts ...DialOption,
) (*Dialer, error) {
	d := &Dialer{
		address:     addr,
		storage:     store,
		dialTimeout: 10 * time.Second,
		handshakeOpts: handshakeOpts{
			remoteVerifier: defaultRemoteVerifier,
			timeout:        30 * time.Second,
		},
	}

	for _, opt := range opts {
		if err := opt(d); err != nil {
			return nil, err
		}
	}

	at, err := d.storage.Attester()
	if err != nil {
		return nil, fmt.Errorf("loading attester: %w", err)
	}
	d.attest = at
	if d.clientName == "" {
		d.clientName = fingerprint.Sum(at.MarshalPublicKey())
	}

	return d, nil
}

// DialOption configures the dialer. Returning an error from an option causes
// [NewDialer] to fail immediately with that error.
type DialOption func(*Dialer) error

// DialWithRemoteVerifier sets a custom remote verifier function.
func DialWithRemoteVerifier(verifier RemoteVerifier) DialOption {
	return func(d *Dialer) error {
		d.handshakeOpts.remoteVerifier = verifier
		return nil
	}
}

// DialWithFunc sets a custom dial function for the dialer. When set, the
// dialer uses this function instead of the default TCP dial. This is the
// dial-side equivalent of [ServeWithListener].
func DialWithFunc(
	fn func(addr string) (Conn, error), opts ...ConnOption,
) DialOption {
	return func(d *Dialer) error {
		d.dialFunc = fn
		d.connOpts = opts
		return nil
	}
}

// DialWithTCP configures the dialer to use TCP connections. This is the default
// behavior, so this option is only needed for explicitness or to set connection
// options. The dialer will fail at [NewDialer] time if the TCP dialer cannot be
// created.
func DialWithTCP(opts ...ConnOption) DialOption {
	return func(d *Dialer) error {
		d.dialFunc = func(addr string) (Conn, error) {
			c, err := net.DialTimeout("tcp", addr, d.dialTimeout)
			if err != nil {
				return nil, fmt.Errorf("dialing tcp: %w", err)
			}
			return newConn(c, opts...), nil
		}
		return nil
	}
}

// DialWithUDP configures the dialer to use UDP/KCP connections. The dialer
// will fail at [NewDialer] time if the UDP dialer cannot be created.
func DialWithUDP(opts ...ConnOption) DialOption {
	return func(d *Dialer) error {
		d.dialFunc = func(addr string) (Conn, error) {
			c, err := kcp.Dial(addr)
			if err != nil {
				return nil, fmt.Errorf("dialing udp: %w", err)
			}
			return newConn(c, opts...), nil
		}
		return nil
	}
}

// DialWithDialTimeout sets the timeout for establishing connections.
func DialWithDialTimeout(timeout time.Duration) DialOption {
	return func(d *Dialer) error {
		d.dialTimeout = timeout
		return nil
	}
}

// DialWithClientName sets the client's advertised name.
func DialWithClientName(name string) DialOption {
	return func(d *Dialer) error {
		d.clientName = name
		return nil
	}
}
