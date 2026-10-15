package kamune

import (
	"context"
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
// It is DialContext(context.Background()).
func (d *Dialer) Dial() (*Transport, error) {
	return d.DialContext(context.Background())
}

// DialContext dials and runs the v2 handshake. The handshake ends when ctx
// ends. The returned error wraps ctx.Err() in that case.
func (d *Dialer) DialContext(ctx context.Context) (*Transport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	cn, err := d.dial(ctx, d.address)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("dialing: %w", ctx.Err())
		}
		return nil, fmt.Errorf("dialing: %w", err)
	}
	transport, err := d.handshake(ctx, cn)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("handshake: %w", ctx.Err())
		}
		return nil, fmt.Errorf("handshake: %w", err)
	}
	return transport, nil
}

func (d *Dialer) dial(ctx context.Context, addr string) (Conn, error) {
	if d.dialFunc != nil {
		return d.dialFunc(addr)
	}
	var nd net.Dialer
	nd.Timeout = d.dialTimeout
	c, err := nd.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dialing tcp: %w", err)
	}
	return newConn(c, d.connOpts...), nil
}

func (d *Dialer) handshake(
	ctx context.Context, cn Conn,
) (t *Transport, err error) {
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
	t, err = runInitiator(ctx, cn, initiatorInput{
		attest:        d.attest,
		store:         d.storage,
		verify:        d.handshakeOpts.remoteVerifier,
		pin:           d.handshakeOpts.pin,
		resumeSID:     d.handshakeOpts.sessionID,
		resumeOnly:    d.handshakeOpts.resumeOnly,
		noPersistence: d.handshakeOpts.noPersistence,
		verifyTimeout: d.handshakeOpts.verifyTimeout,
		name:          d.clientName,
		version:       d.version,
	})
	if err != nil {
		return nil, err
	}
	slog.Info(
		"session established",
		slog.String("session_id", t.sessionID),
		slog.Bool("resumed", t.resumed),
	)
	return t, nil
}

// PublicKey returns the dialer's public key.
func (d *Dialer) PublicKey() []byte {
	return d.attest.MarshalPublicKey()
}

// NewDialer creates a new dialer with the given address, storage, and options.
// It returns ErrMissingStorage when store is nil, ErrMissingVerifier when rv
// is nil, and an error when [AppVersion] is not a valid version.
func NewDialer(
	addr string, store *storage.Storage, rv RemoteVerifier, opts ...DialOption,
) (*Dialer, error) {
	if store == nil {
		return nil, ErrMissingStorage
	}
	if rv == nil {
		return nil, ErrMissingVerifier
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
	if d.handshakeOpts.noPersistence && d.handshakeOpts.sessionID != "" {
		return nil, fmt.Errorf(
			"dial: resume requires persistence",
		)
	}
	if len(d.handshakeOpts.pin) > 0 &&
		!attest.IsValidPublicKey(d.handshakeOpts.pin) {
		return nil, fmt.Errorf("dial: peer key is not a valid public key")
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
// [ValidatePeerName], or [NewDialer] fails, since peers reject a handshake
// whose name fails it. An empty name stands for the default, the
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

// DialWithResume offers to resume sessionID. The stored peer key of the
// initiator row is pinned. A cold answer is a new session unless
// [DialWithResumeOnly] is set. The verifier runs either way.
func DialWithResume(sessionID string) DialOption {
	return func(d *Dialer) error {
		d.handshakeOpts.sessionID = sessionID
		return nil
	}
}

// DialWithResumeOnly fails the dial when the peer does not resume sessionID.
func DialWithResumeOnly() DialOption {
	return func(d *Dialer) error {
		d.handshakeOpts.resumeOnly = true
		return nil
	}
}

// DialWithPeerKey pins the peer's PKIX public key. NewDialer fails when
// pub is not a valid identity key.
func DialWithPeerKey(pub []byte) DialOption {
	return func(d *Dialer) error {
		d.handshakeOpts.pin = append([]byte(nil), pub...)
		return nil
	}
}

// DialWithVerifyTimeout sets how long the [RemoteVerifier] may take to decide
// on a peer. The handshake deadline does not run while the verifier does, so
// a user has this long to compare fingerprints; a verifier that accepts later
// is treated as a rejection. The dialer also allows this long for the
// server's verifier when it waits for the server's answer, so a lower d
// also makes [Dialer.Dial] give up sooner on a server that does not answer.
// The default is 150 seconds; d must be positive.
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
// storage, for incognito use. A session it establishes stores no resumption
// row, and closing it writes nothing either. It cannot be resumed.
// [NewDialer] rejects this option together with [DialWithResume].
//
// The storage is still read for the dialer's identity and handed to the
// [RemoteVerifier], which decides on its own whether to store the peer.
func DialWithoutPersistence() DialOption {
	return func(d *Dialer) error {
		d.handshakeOpts.noPersistence = true
		return nil
	}
}
