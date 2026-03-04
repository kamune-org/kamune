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
)

// Dialer handles outgoing connections and initiates handshakes.
type Dialer struct {
	attester         attest.Attester
	conn             Conn
	sessionManager   *SessionManager
	storage          *Storage
	clientName       string
	address          string
	handshakeOpts    handshakeOpts
	storageOpts      []StorageOption
	connOpts         []ConnOption
	resumptionConfig ResumptionConfig
	connType         connType
	writeTimeout     time.Duration
	dialTimeout      time.Duration
	readTimeout      time.Duration
	algorithm        attest.Algorithm
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

	// Save session for potential resumption
	if d.resumptionConfig.Enabled && d.resumptionConfig.PersistSessions {
		err := SaveSessionForResumption(transport, d.sessionManager)
		if err != nil {
			slog.Warn(
				"failed to save session for resumption",
				slog.Any("error", err),
				slog.String("session_id", transport.SessionID()),
			)
		}
	}

	return transport, nil
}

// DialWithResume attempts to resume an existing session with the given peer,
// falling back to a fresh handshake if resumption fails.
func (d *Dialer) DialWithResume(
	remotePublicKey []byte,
) (*Transport, bool, error) {
	if !d.resumptionConfig.Enabled || len(remotePublicKey) == 0 {
		t, err := d.Dial()
		return t, false, err
	}

	// Check if we have a resumable session
	state, err := d.sessionManager.LoadSessionByPublicKey(remotePublicKey)
	if err != nil {
		// No existing session, do fresh handshake
		slog.Debug("no existing session found, performing fresh handshake")
		t, err := d.Dial()
		return t, false, err
	}

	// Check if session is resumable
	if state.Phase != PhaseEstablished || len(state.SharedSecret) == 0 {
		slog.Debug(
			"session not resumable, performing fresh handshake",
			slog.String("phase", state.Phase.String()),
		)
		t, err := d.Dial()
		return t, false, err
	}

	// Attempt resumption
	t, err := d.attemptResumption(state)
	if err != nil {
		slog.Warn(
			"resumption failed, falling back to fresh handshake",
			slog.Any("error", err),
		)
		// Close any existing connection and retry fresh
		if d.conn != nil {
			_ = d.conn.Close()
			d.conn = nil
		}
		t, err := d.Dial()
		return t, false, err
	}

	slog.Info("session resumed", slog.String("session_id", t.SessionID()))

	return t, true, nil
}

// DialWithReconnect attempts to resume an existing session or establishes a new
// one if resumption fails.
func (d *Dialer) DialWithReconnect(
	sessionState *SessionState,
) (*Transport, error) {
	if sessionState == nil {
		return d.Dial()
	}

	// Try to reconnect with existing session
	c, err := d.dial(d.address)
	if err != nil {
		return nil, fmt.Errorf("dialing for reconnect: %w", err)
	}
	d.conn = c

	// Attempt session resumption
	transport, err := d.attemptResumption(sessionState)
	if err != nil {
		slog.Warn(
			"reconnection failed, falling back to fresh handshake",
			slog.Any("error", err),
		)
		// Close the failed connection and try fresh
		_ = d.conn.Close()
		d.conn = nil
		return d.Dial()
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

func (d *Dialer) attemptResumption(state *SessionState) (*Transport, error) {
	// Establish connection if needed
	if d.conn == nil {
		c, err := d.dial(d.address)
		if err != nil {
			return nil, fmt.Errorf("dialing for resumption: %w", err)
		}
		d.conn = c
	}

	// Delegate the entire challenge-response protocol to SessionResumer.
	resumer := NewSessionResumer(
		d.storage,
		d.sessionManager,
		d.attester,
		d.resumptionConfig.MaxSessionAge,
	)

	transport, err := resumer.InitiateResumption(d.conn, state)
	if err != nil {
		return nil, fmt.Errorf("initiating resumption: %w", err)
	}

	// Update session state
	if d.resumptionConfig.PersistSessions {
		if err := SaveSessionForResumption(transport, d.sessionManager); err != nil {
			slog.Warn(
				"failed to update session after resumption",
				slog.Any("error", err),
			)
		}
	}

	return transport, nil
}

// PublicKey returns the dialer's public key.
func (d *Dialer) PublicKey() PublicKey {
	return d.attester.PublicKey()
}

// SessionManager returns the dialer's session manager.
func (d *Dialer) SessionManager() *SessionManager {
	return d.sessionManager
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
		address:          addr,
		connType:         tcp,
		algorithm:        attest.Ed25519Algorithm,
		readTimeout:      5 * time.Minute,
		writeTimeout:     1 * time.Minute,
		dialTimeout:      10 * time.Second,
		resumptionConfig: DefaultResumptionConfig(),
		handshakeOpts: handshakeOpts{
			remoteVerifier: defaultRemoteVerifier,
			timeout:        30 * time.Second,
		},
	}

	for _, opt := range opts {
		opt(d)
	}

	storage, err := OpenStorage(d.storageOpts...)
	if err != nil {
		return nil, fmt.Errorf("opening storage: %w", err)
	}

	at, err := storage.attester()
	if err != nil {
		return nil, fmt.Errorf("loading attester: %w", err)
	}

	d.storage = storage
	d.attester = at
	d.clientName = fingerprint.Sum(at.PublicKey().Marshal())

	// Initialize session manager for resumption
	d.sessionManager = NewSessionManager(
		storage, d.resumptionConfig.MaxSessionAge,
	)

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
func DialWithStorageOpts(opts ...StorageOption) DialOption {
	return func(d *Dialer) { d.storageOpts = opts }
}

// DialWithResumption configures session resumption settings.
func DialWithResumption(config ResumptionConfig) DialOption {
	return func(d *Dialer) { d.resumptionConfig = config }
}

// DialWithResumptionEnabled enables or disables session resumption.
func DialWithResumptionEnabled(enabled bool) DialOption {
	return func(d *Dialer) { d.resumptionConfig.Enabled = enabled }
}

// DialWithSessionTimeout sets the maximum age for resumable sessions.
func DialWithSessionTimeout(timeout time.Duration) DialOption {
	return func(d *Dialer) { d.resumptionConfig.MaxSessionAge = timeout }
}
