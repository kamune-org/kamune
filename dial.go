package kamune

import (
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"google.golang.org/protobuf/proto"

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/pkg/fingerprint"
)

// Dialer handles outgoing connections and initiates handshakes.
type Dialer struct {
	conn             Conn
	attester         attest.Attester
	storage          *Storage
	clientName       string
	address          string
	handshakeOpts    handshakeOpts
	storageOpts      []StorageOption
	connOpts         []ConnOption
	connType         connType
	writeTimeout     time.Duration
	dialTimeout      time.Duration
	readTimeout      time.Duration
	algorithm        attest.Algorithm
	sessionManager   *SessionManager
	resumptionConfig ResumptionConfig
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
		if err := SaveSessionForResumption(transport, d.sessionManager); err != nil {
			slog.Warn("failed to save session for resumption",
				slog.Any("error", err),
				slog.String("session_id", transport.SessionID()),
			)
		}
	}

	return transport, nil
}

// DialWithResume attempts to resume an existing session with the given peer,
// falling back to a fresh handshake if resumption fails.
func (d *Dialer) DialWithResume(remotePublicKey []byte) (*Transport, bool, error) {
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
		slog.Debug("session not resumable, performing fresh handshake",
			slog.String("phase", state.Phase.String()),
		)
		t, err := d.Dial()
		return t, false, err
	}

	// Attempt resumption
	t, err := d.attemptResumption(state)
	if err != nil {
		slog.Warn("resumption failed, falling back to fresh handshake",
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

	slog.Info(
		"session resumed",
		slog.String("session_id", t.SessionID()),
	)

	return t, true, nil
}

// DialWithReconnect attempts to resume an existing session or establishes
// a new one if resumption fails.
func (d *Dialer) DialWithReconnect(sessionState *SessionState) (*Transport, error) {
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
		slog.Warn("reconnection failed, falling back to fresh handshake",
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

	// Step 1: Send our introduction
	if err := sendIntroduction(d.conn, d.clientName, d.attester, d.algorithm); err != nil {
		return nil, fmt.Errorf("send introduction: %w", err)
	}

	// Step 2: Receive peer's introduction with route validation
	st, route, err := readSignedTransport(d.conn)
	if err != nil {
		return nil, fmt.Errorf("read transport: %w", err)
	}

	// Validate route (allow RouteInvalid for backward compatibility)
	if route != RouteIdentity && route != RouteInvalid {
		return nil, fmt.Errorf("%w: expected %s, got %s",
			ErrUnexpectedRoute, RouteIdentity, route)
	}

	peer, err := receiveIntroduction(st)
	if err != nil {
		return nil, fmt.Errorf("receive introduction: %w", err)
	}

	if err := d.handshakeOpts.remoteVerifier(d.storage, peer); err != nil {
		return nil, fmt.Errorf("verify remote: %w", err)
	}

	// Step 3: Proceed with encrypted handshake
	pt := newPlainTransport(d.conn, peer.PublicKey, d.attester, d.storage)
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

func (d *Dialer) attemptResumption(state *SessionState) (*Transport, error) {
	// Establish connection if needed
	if d.conn == nil {
		c, err := d.dial(d.address)
		if err != nil {
			return nil, fmt.Errorf("dialing for resumption: %w", err)
		}
		d.conn = c
	}

	// Generate a challenge for the server to prove it has the shared secret
	challenge := randomBytes(resumeChallengeSize)

	// Create and send reconnect request
	req := &pb.ReconnectRequest{
		SessionId:        state.SessionID,
		LastPhase:        state.Phase.ToProto(),
		LastSendSequence: state.SendSequence,
		LastRecvSequence: state.RecvSequence,
		RemotePublicKey:  d.attester.PublicKey().Marshal(),
		ResumeChallenge:  challenge,
	}

	if err := d.sendSignedMessage(req, RouteReconnect); err != nil {
		return nil, fmt.Errorf("sending reconnect request: %w", err)
	}

	// Receive response
	respPayload, err := d.conn.ReadBytes()
	if err != nil {
		return nil, fmt.Errorf("reading reconnect response: %w", err)
	}

	var respST pb.SignedTransport
	if err := proto.Unmarshal(respPayload, &respST); err != nil {
		return nil, fmt.Errorf("unmarshaling response transport: %w", err)
	}

	// Verify signature from the server
	remoteKey, err := d.storage.algorithm.Identitfier().ParsePublicKey(state.RemotePublicKey)
	if err != nil {
		return nil, fmt.Errorf("parsing remote public key: %w", err)
	}

	if !d.storage.algorithm.Identitfier().Verify(remoteKey, respST.Data, respST.Signature) {
		return nil, ErrInvalidSignature
	}

	var resp pb.ReconnectResponse
	if err := proto.Unmarshal(respST.Data, &resp); err != nil {
		return nil, fmt.Errorf("unmarshaling response: %w", err)
	}

	if !resp.Accepted {
		return nil, fmt.Errorf("%w: %s", ErrResumptionFailed, resp.ErrorMessage)
	}

	// Verify the server's challenge response
	resumer := NewSessionResumer(
		d.storage, d.sessionManager, d.attester, d.resumptionConfig.MaxSessionAge,
	)
	expectedResponse := resumer.computeChallengeResponse(challenge, state.SharedSecret)
	if !hmacEqual(resp.ChallengeResponse, expectedResponse) {
		return nil, ErrChallengeVerifyFailed
	}

	// Compute our response to the server's challenge
	clientChallengeResponse := resumer.computeChallengeResponse(
		resp.ServerChallenge, state.SharedSecret,
	)

	// Determine the sequence numbers to use
	resumeSendSeq, resumeRecvSeq := resumer.reconcileSequences(
		state.SendSequence,
		state.RecvSequence,
		resp.ServerRecvSequence,
		resp.ServerSendSequence,
	)

	// Send verification
	verify := &pb.ReconnectVerify{
		ChallengeResponse: clientChallengeResponse,
		Verified:          true,
	}
	if err := d.sendSignedMessage(verify, RouteReconnect); err != nil {
		return nil, fmt.Errorf("sending verification: %w", err)
	}

	// Receive completion
	completePayload, err := d.conn.ReadBytes()
	if err != nil {
		return nil, fmt.Errorf("reading completion: %w", err)
	}

	var completeST pb.SignedTransport
	if err := proto.Unmarshal(completePayload, &completeST); err != nil {
		return nil, fmt.Errorf("unmarshaling completion transport: %w", err)
	}

	if !d.storage.algorithm.Identitfier().Verify(
		remoteKey, completeST.Data, completeST.Signature,
	) {
		return nil, ErrInvalidSignature
	}

	var complete pb.ReconnectComplete
	if err := proto.Unmarshal(completeST.Data, &complete); err != nil {
		return nil, fmt.Errorf("unmarshaling completion: %w", err)
	}

	if !complete.Success {
		return nil, fmt.Errorf("%w: %s", ErrResumptionFailed, complete.ErrorMessage)
	}

	// Use the agreed-upon sequence numbers
	if complete.ResumeSendSequence > 0 {
		resumeSendSeq = complete.ResumeSendSequence
	}
	if complete.ResumeRecvSequence > 0 {
		resumeRecvSeq = complete.ResumeRecvSequence
	}

	// Restore the transport
	transport, err := resumer.restoreTransport(
		d.conn, state, resumeSendSeq, resumeRecvSeq,
	)
	if err != nil {
		return nil, fmt.Errorf("restoring transport: %w", err)
	}

	// Update session state
	if d.resumptionConfig.PersistSessions {
		if err := SaveSessionForResumption(transport, d.sessionManager); err != nil {
			slog.Warn("failed to update session after resumption",
				slog.Any("error", err),
			)
		}
	}

	return transport, nil
}

func (d *Dialer) sendSignedMessage(msg Transferable, route Route) error {
	data, err := proto.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshaling message: %w", err)
	}

	sig, err := d.attester.Sign(data)
	if err != nil {
		return fmt.Errorf("signing message: %w", err)
	}

	st := &pb.SignedTransport{
		Data:      data,
		Signature: sig,
		Padding:   padding(maxPadding),
		Route:     route.ToProto(),
	}

	payload, err := proto.Marshal(st)
	if err != nil {
		return fmt.Errorf("marshaling transport: %w", err)
	}

	return d.conn.WriteBytes(payload)
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
			ratchetThreshold: defaultRatchetThreshold,
			remoteVerifier:   defaultRemoteVerifier,
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

	// Initialize session manager for resumption
	d.sessionManager = NewSessionManager(storage, d.resumptionConfig.MaxSessionAge)

	sum := sha256.Sum256(at.PublicKey().Marshal())
	d.clientName = fingerprint.Base64(sum[:])

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

// DialWithRatchetThreshold sets the message threshold for DH ratchet rotation.
func DialWithRatchetThreshold(threshold uint64) DialOption {
	return func(d *Dialer) { d.handshakeOpts.ratchetThreshold = threshold }
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
