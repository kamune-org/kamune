package kamune

import (
	"crypto/hpke"
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"
	"time"

	"github.com/xtaci/kcp-go/v5"

	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
)

// Dialer handles outgoing connections and initiates handshakes.
type Dialer struct {
	attester      attest.Attester
	conn          Conn
	storage       *storage.Storage
	clientName    string
	address       string
	handshakeOpts handshakeOpts
	storageOpts   []storage.StorageOption
	connOpts      []ConnOption
	connType      connType
	writeTimeout  time.Duration
	dialTimeout   time.Duration
	readTimeout   time.Duration
	algorithm     attest.Algorithm
}

// Dial establishes a connection and performs the handshake.
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

	return transport, nil
}

func (d *Dialer) dial(addr string) (*conn, error) {
	switch d.connType {
	case tcp:
		c, err := net.DialTimeout("tcp", addr, d.dialTimeout)
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

	// Bound the handshake to avoid indefinite blocking.
	_ = d.conn.SetDeadline(time.Now().Add(d.handshakeOpts.timeout))
	defer func() { _ = d.conn.SetDeadline(time.Time{}) }()

	// Step 0: Exchange HPKE keys to derive an encrypted connection for the
	// handshake
	ec, err := initiateExchange(d.conn)
	if err != nil {
		return nil, fmt.Errorf("initating exchange: %w", err)
	}

	// Step 1: Send our introduction
	err = sendIntroduction(ec, d.clientName, d.attester, d.algorithm)
	if err != nil {
		return nil, fmt.Errorf("send introduction: %w", err)
	}

	// Step 2: Receive peer's introduction with route validation
	st, route, err := readSignedTransport(ec)
	if err != nil {
		return nil, fmt.Errorf("read transport: %w", err)
	}

	// Validate route
	if route != RouteIdentity {
		return nil, fmt.Errorf(
			"%w: expected %s, got %s", ErrUnexpectedRoute, RouteIdentity, route,
		)
	}

	peer, err := receiveIntroduction(st)
	if err != nil {
		return nil, fmt.Errorf("receive introduction: %w", err)
	}
	if err := d.handshakeOpts.remoteVerifier(d.storage, peer); err != nil {
		return nil, fmt.Errorf("verify remote: %w", err)
	}

	// Step 3: Proceed with the handshake
	pt := newUnderlyingTransport(d.conn, ec, peer.PublicKey, d.attester, d.storage)
	t, err := requestHandshake(pt, d.handshakeOpts)
	if err != nil {
		return nil, fmt.Errorf("request handshake: %w", err)
	}

	slog.Info(
		"session established",
		slog.String("session_id", t.SessionID()),
		slog.String("peer", peer.Name),
	)

	return t, nil
}

func initiateExchange(c Conn) (*encryptedConn, error) {
	kem := hpkeKEM()
	kdf := hpkeKDF()
	aead := hpkeAEAD()

	privateKey, err := kem.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generating kem key: %w", err)
	}
	if err := c.WriteBytes(privateKey.PublicKey().Bytes()); err != nil {
		return nil, fmt.Errorf("writing hpke public key: %w", err)
	}
	remoteEnc, err := c.ReadBytes()
	if err != nil {
		return nil, fmt.Errorf("reading remote ciphertext: %w", err)
	}
	recipient, err := hpke.NewRecipient(remoteEnc, privateKey, kdf, aead, nil)
	if err != nil {
		return nil, fmt.Errorf("creating recipient: %w", err)
	}

	remotePublicBytes, err := c.ReadBytes()
	if err != nil {
		return nil, fmt.Errorf("reading remote public key: %w", err)
	}
	remotePublic, err := kem.NewPublicKey(remotePublicBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing remote public key: %w", err)
	}
	enc, sender, err := hpke.NewSender(remotePublic, kdf, aead, nil)
	if err != nil {
		return nil, fmt.Errorf("creating sender: %w", err)
	}
	if err := c.WriteBytes(enc); err != nil {
		return nil, fmt.Errorf("writing ciphertext: %w", err)
	}

	return newEncryptedConn(c, sender, recipient), nil
}

// PublicKey returns the dialer's public key.
func (d *Dialer) PublicKey() PublicKey {
	return d.attester.PublicKey()
}

// Close closes the dialer's storage.
func (d *Dialer) Close() error {
	if d.storage != nil {
		return d.storage.Close()
	}
	return nil
}

// NewDialer creates a new dialer with the given address and options.
func NewDialer(addr string, opts ...DialOption) (*Dialer, error) {
	d := &Dialer{
		address:      addr,
		connType:     tcp,
		algorithm:    attest.Ed25519Algorithm,
		readTimeout:  5 * time.Minute,
		writeTimeout: 1 * time.Minute,
		dialTimeout:  10 * time.Second,
		handshakeOpts: handshakeOpts{
			remoteVerifier: defaultRemoteVerifier,
			timeout:        30 * time.Second,
		},
	}

	for _, opt := range opts {
		opt(d)
	}

	storage, err := storage.OpenStorage(d.storageOpts...)
	if err != nil {
		return nil, fmt.Errorf("opening storage: %w", err)
	}

	at, err := storage.Attester()
	if err != nil {
		return nil, fmt.Errorf("loading attester: %w", err)
	}

	d.storage = storage
	d.attester = at
	d.clientName = fingerprint.Sum(at.PublicKey().Marshal())

	return d, nil
}

// DialOption configures the dialer.
type DialOption func(*Dialer)

// DialWithRemoteVerifier sets a custom remote verifier function.
func DialWithRemoteVerifier(verifier RemoteVerifier) DialOption {
	return func(d *Dialer) { d.handshakeOpts.remoteVerifier = verifier }
}

// DialWithExistingConn uses an existing connection instead of dialing.
func DialWithExistingConn(conn Conn) DialOption {
	return func(d *Dialer) { d.conn = conn }
}

// DialWithReadTimeout sets the read timeout for connections.
func DialWithReadTimeout(timeout time.Duration) DialOption {
	return func(d *Dialer) { d.readTimeout = timeout }
}

// DialWithWriteTimeout sets the write timeout for connections.
func DialWithWriteTimeout(timeout time.Duration) DialOption {
	return func(d *Dialer) { d.writeTimeout = timeout }
}

// DialWithDialTimeout sets the timeout for establishing connections.
func DialWithDialTimeout(timeout time.Duration) DialOption {
	return func(d *Dialer) { d.dialTimeout = timeout }
}

// DialWithAlgorithm sets the cryptographic algorithm for identity.
func DialWithAlgorithm(a attest.Algorithm) DialOption {
	return func(d *Dialer) { d.algorithm = a }
}

// DialWithTCPConn configures the dialer to use TCP connections.
func DialWithTCPConn(opts ...ConnOption) DialOption {
	return func(d *Dialer) { d.connType = tcp; d.connOpts = opts }
}

// DialWithUDPConn configures the dialer to use UDP/KCP connections.
func DialWithUDPConn(opts ...ConnOption) DialOption {
	return func(d *Dialer) { d.connType = udp; d.connOpts = opts }
}

// DialWithClientName sets the client's advertised name.
func DialWithClientName(name string) DialOption {
	return func(d *Dialer) { d.clientName = name }
}

// DialWithStorageOpts sets storage options.
func DialWithStorageOpts(opts ...storage.StorageOption) DialOption {
	return func(d *Dialer) { d.storageOpts = opts }
}
