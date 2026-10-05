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
	version       string
	address       string
	connOpts      []ConnOption
	handshakeOpts handshakeOpts
	dialTimeout   time.Duration
}

// Dial establishes a connection and performs the handshake.
//
// After sending its introduction, Dial waits for the server's introduction
// for up to the handshake timeout of 30 seconds plus the verify limit (see
// [DialWithVerifyTimeout]), because the server's user may be comparing
// fingerprints. Dial cannot tell such a server from one that has stalled,
// or from an older server whose own 30-second limit runs out while its user
// verifies, so against those Dial can take up to 3 minutes by default to
// fail.
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

func (d *Dialer) handshake(cn Conn) (t *Transport, err error) {
	defer func() {
		if msg := recover(); msg != nil {
			slog.Error(
				"handshake dial panic",
				slog.Any("message", msg),
				slog.String("stack", string(debug.Stack())),
			)
			cn.Close()
			err = fmt.Errorf("handshake panic: %v", msg)
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

	// Attempt resumption if sessionID is provided.
	if d.handshakeOpts.sessionID != "" {
		t, err = d.attemptResume(ec, cn)
		if err != nil {
			return nil, fmt.Errorf("attempt resume: %w", err)
		}
		return t, nil
	}

	// Step 1: Send our introduction
	err = sendIntroduction(ec, d.attest, d.clientName, d.version)
	if err != nil {
		return nil, fmt.Errorf("send introduction: %w", err)
	}

	// The server runs its verifier before it answers; allow for it.
	_ = cn.SetDeadline(time.Now().Add(
		d.handshakeOpts.timeout + d.handshakeOpts.verifyTimeout,
	))

	// Step 2: Receive peer's introduction
	st, err := readSignedTransport(ec)
	if err != nil {
		return nil, fmt.Errorf("read transport: %w", err)
	}

	// Validate route
	r, err := routeFromST(st)
	if err != nil {
		return nil, fmt.Errorf("extracting route: %w", err)
	}
	if r != RouteIdentity {
		return nil, fmt.Errorf(
			"%w: expected %s, got %s", ErrUnexpectedRoute, RouteIdentity, r,
		)
	}

	peer, remoteVersion, err := receiveIntroduction(st)
	if err != nil {
		return nil, fmt.Errorf("receive introduction: %w", err)
	}

	if err := checkVersion(d.version, remoteVersion); err != nil {
		return nil, fmt.Errorf("version check: %w", err)
	}

	err = verifyPeer(cn, d.handshakeOpts, d.storage, peer, false)
	if err != nil {
		return nil, fmt.Errorf("verify remote: %w", err)
	}
	serde := newSignedSerde(peer.PublicKey, d.attest)

	// Step 3: Proceed with the handshake
	t, err = requestHandshake(ec, serde, d.handshakeOpts)
	if err != nil {
		return nil, fmt.Errorf("request handshake: %w", err)
	}

	// Since from now on all communications are encrypted via the newly ciphers
	// derived from the handshake, we can switch to the plain connection.
	t.conn = cn
	t.remotePeer = peer
	d.handshakeOpts.recordSession(d.storage, t, true)

	slog.Info(
		"session established",
		slog.String("session_id", t.sessionID),
		slog.String("peer", peer.Name),
	)

	return t, nil
}

// attemptResume tries to resume a session. On failure Dial returns the
// error; the application may open a new connection and use Introduction.
func (d *Dialer) attemptResume(
	ec *exchange.Channel, cn Conn,
) (*Transport, error) {
	sessionID := d.handshakeOpts.sessionID
	token, err := d.storage.PopList(sessionID, storage.ResumptionTokensKey)
	if err != nil {
		return nil, fmt.Errorf("getting resumption token: %w", err)
	}
	remaining := remainingResumptionTokens(d.storage, sessionID)
	peer, err := d.storage.GetPeer(sessionID)
	if err != nil {
		return nil, fmt.Errorf("getting session peer: %w", err)
	}

	// Send ResumeRequest.
	err = sendResumeRequest(ec, d.attest, sessionID, token)
	if err != nil {
		return nil, fmt.Errorf("sending resume request: %w", err)
	}

	// Receive ResumeAccept.
	accepted, reason, err := receiveResumeAccept(ec, peer.PublicKey)
	switch {
	case err != nil:
		return nil, fmt.Errorf("receiving resume accept: %w", err)
	case !accepted:
		return nil, fmt.Errorf("%w: %s", ErrResumptionRejected, reason)
	}

	// Resume accepted — proceed to handshake with predetermined session ID.
	serde := newSignedSerde(peer.PublicKey, d.attest)
	t, err := requestHandshake(ec, serde, d.handshakeOpts)
	if err != nil {
		return nil, fmt.Errorf("request handshake after resume: %w", err)
	}

	t.conn = cn
	t.remotePeer = peer
	t.tokens = remaining
	d.handshakeOpts.recordSession(d.storage, t, false)

	slog.Info("session resumed", slog.String("session_id", t.sessionID))

	return t, nil
}

// PublicKey returns the dialer's public key.
func (d *Dialer) PublicKey() []byte {
	return d.attest.MarshalPublicKey()
}

// NewDialer creates a new dialer with the given address, storage, and options.
// It returns ErrMissingStorage when store is nil, and an error when
// [AppVersion] is not a valid version.
func NewDialer(
	addr string, store *storage.Storage, rv RemoteVerifier, opts ...DialOption,
) (*Dialer, error) {
	if store == nil {
		return nil, ErrMissingStorage
	}
	version, err := appVersion()
	if err != nil {
		return nil, err
	}
	d := &Dialer{
		version:     version,
		address:     addr,
		storage:     store,
		dialTimeout: 10 * time.Second,
		handshakeOpts: handshakeOpts{
			remoteVerifier: rv,
			timeout:        defaultHandshakeTimeout,
			verifyTimeout:  defaultVerifyTimeout,
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

// DialWithFunc sets a custom dial function for the dialer. When set, the
// dialer uses this function instead of the default TCP dial. This is the
// dial-side equivalent of [ServeWithListener].
func DialWithFunc(fn func(addr string) (Conn, error)) DialOption {
	return func(d *Dialer) error {
		d.dialFunc = fn
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

// DialWithClientName sets the client's advertised name. The name must pass
// [ValidatePeerName], or [NewDialer] fails, since peers reject an
// introduction with such a name. An empty name stands for the default, the
// [fingerprint.Sum] of the dialer's public key.
func DialWithClientName(name string) DialOption {
	return func(d *Dialer) error {
		if err := ValidatePeerName(name); err != nil {
			return fmt.Errorf("client name: %w", err)
		}
		d.clientName = name
		return nil
	}
}

// DialWithResume configures the dialer to attempt session resumption.
//
// A resumption skips the introductions and does not run the
// [RemoteVerifier] on either side: the dialer checks the server's answer
// against the peer key stored for the session, and the server accepts the
// dialer by the key it stored (see [ServeWithResumeEnabled]). When the
// server rejects the request, Dial returns an error wrapping
// [ErrResumptionRejected], for example once 24 hours have passed since the
// session's cold handshake; resuming does not extend that window. The
// application may then dial without this option for a cold handshake,
// which runs the verifier.
func DialWithResume(sessionID string) DialOption {
	return func(d *Dialer) error {
		d.handshakeOpts.sessionID = sessionID
		return nil
	}
}

// DialWithVerifyTimeout sets how long the [RemoteVerifier] may take to decide
// on a peer. The handshake deadline does not run while the verifier does, so
// a user has this long to compare fingerprints; a verifier that accepts later
// is treated as a rejection. The dialer also allows this long for the
// server's verifier when it waits for the server's introduction, so a lower
// d also makes [Dialer.Dial] give up sooner on a server that does not
// answer. The default is 150 seconds; d must be positive.
func DialWithVerifyTimeout(d time.Duration) DialOption {
	return func(dl *Dialer) error {
		if d <= 0 {
			return fmt.Errorf("verify timeout is not positive: %v", d)
		}
		dl.handshakeOpts.verifyTimeout = d
		return nil
	}
}

// DialWithoutPersistence keeps the dialer from writing session state to
// storage, for incognito use. Sessions it establishes leave no session
// record: no peer key, established_at or resumption tokens are stored, and
// closing such a session writes nothing either. Those sessions cannot be
// resumed.
//
// The storage is still read for the dialer's identity and handed to the
// [RemoteVerifier], which decides on its own whether to store the peer. With
// [DialWithResume], the dialer still consumes a stored token of the session
// it resumes, but stores no new ones, and the session's remaining tokens are
// still invalidated when it ends, or when a transport that it replaced is
// closed (see [Transport.Close]).
func DialWithoutPersistence() DialOption {
	return func(d *Dialer) error {
		d.handshakeOpts.noPersistence = true
		return nil
	}
}
