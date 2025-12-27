package kamune

import (
	"crypto/sha256"
	"errors"
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

// Server handles incoming connections and manages the handshake process.
type Server struct {
	attester         attest.Attester
	storage          *Storage
	handlerFunc      HandlerFunc
	sessionManager   *SessionManager
	addr             string
	serverName       string
	handshakeOpts    handshakeOpts
	connOpts         []ConnOption
	storageOpts      []StorageOption
	resumptionConfig ResumptionConfig
	algorithm        attest.Algorithm
	connType         connType
}

// ListenAndServe starts the server and listens for incoming connections.
func (s *Server) ListenAndServe() error {
	defer func() {
		if err := s.storage.Close(); err != nil {
			slog.Warn("closing storage", slog.Any("error", err))
		}
	}()

	l, err := s.listen()
	if err != nil {
		return fmt.Errorf("listening: %w", err)
	}
	defer func() {
		if err := l.Close(); err != nil {
			slog.Warn("closing listener", slog.Any("error", err))
		}
	}()

	slog.Info("server started", slog.String("addr", s.addr))

	for {
		c, err := l.Accept()
		if err != nil {
			// Exit cleanly when the listener is closed (shutdown).
			if errors.Is(err, net.ErrClosed) {
				return nil
			}

			slog.Error("accept conn", slog.Any("error", err))
			continue
		}
		go s.handleConnection(c)
	}
}

func (s *Server) listen() (net.Listener, error) {
	switch s.connType {
	case tcp:
		return net.Listen("tcp", s.addr)
	case udp:
		return kcp.Listen(s.addr)
	default:
		panic(fmt.Sprintf("unknown conn type: %v", s.connType))
	}
}

func (s *Server) handleConnection(c net.Conn) {
	cn, err := newConn(c, s.connOpts...)
	if err != nil {
		slog.Error("new conn", slog.Any("error", err))
		return
	}

	if err := s.serve(cn); err != nil {
		slog.Error("serve conn",
			slog.Any("error", err),
			slog.String("remote", c.RemoteAddr().String()),
		)
	}
}

func (s *Server) serve(cn Conn) error {
	defer func() {
		if msg := recover(); msg != nil {
			slog.Error(
				"serve panic",
				slog.Any("message", msg),
				slog.String("stack", string(debug.Stack())),
			)
		}
		if err := cn.Close(); err != nil && !errors.Is(err, ErrConnClosed) {
			slog.Error("close conn", slog.Any("err", err))
		}
	}()

	// Step 1: Receive introduction with route validation
	st, route, err := readSignedTransport(cn)
	if err != nil {
		return fmt.Errorf("reading transport: %w", err)
	}

	// Handle different routes at this stage
	switch route {
	case RouteIdentity, RouteInvalid:
		// RouteInvalid for backward compatibility
		return s.handleNewConnection(cn, st)
	case RouteReconnect:
		return s.handleReconnection(cn, st)
	default:
		return fmt.Errorf("%w: expected %s or %s, got %s",
			ErrUnexpectedRoute, RouteIdentity, RouteReconnect, route)
	}
}

func (s *Server) handleNewConnection(cn Conn, st *pb.SignedTransport) error {
	peer, err := receiveIntroduction(st)
	if err != nil {
		return fmt.Errorf("receiving introduction: %w", err)
	}

	if err := s.handshakeOpts.remoteVerifier(s.storage, peer); err != nil {
		return fmt.Errorf("verify remote: %w", err)
	}

	if err := sendIntroduction(cn, s.serverName, s.attester, s.algorithm); err != nil {
		return fmt.Errorf("sending introduction: %w", err)
	}

	pt := newPlainTransport(cn, peer.PublicKey, s.attester, s.storage)
	t, err := acceptHandshake(pt, s.handshakeOpts)
	if err != nil {
		return fmt.Errorf("accepting handshake: %w", err)
	}

	slog.Info("session established",
		slog.String("session_id", t.SessionID()),
		slog.String("peer", peer.Name),
	)

	// Save session for potential resumption
	if s.resumptionConfig.Enabled && s.resumptionConfig.PersistSessions {
		if err := SaveSessionForResumption(t, s.sessionManager); err != nil {
			slog.Warn("failed to save session for resumption",
				slog.Any("error", err),
				slog.String("session_id", t.SessionID()),
			)
		}
	}

	if err := s.handlerFunc(t); err != nil {
		return fmt.Errorf("handler: %w", err)
	}

	return nil
}

func (s *Server) handleReconnection(cn Conn, st *pb.SignedTransport) error {
	if !s.resumptionConfig.Enabled {
		slog.Warn("reconnection attempted but resumption is disabled")
		return s.sendReconnectReject(cn, "session resumption is disabled")
	}

	// Parse the reconnect request from the signed transport
	var req pb.ReconnectRequest
	if err := proto.Unmarshal(st.Data, &req); err != nil {
		return fmt.Errorf("unmarshaling reconnect request: %w", err)
	}

	// Verify the signature using the claimed public key
	remoteKey, err := s.algorithm.Identitfier().ParsePublicKey(req.RemotePublicKey)
	if err != nil {
		return s.sendReconnectReject(cn, "invalid public key")
	}

	if !s.algorithm.Identitfier().Verify(remoteKey, st.Data, st.Signature) {
		return s.sendReconnectReject(cn, "signature verification failed")
	}

	slog.Info("reconnection request received",
		slog.String("session_id", req.SessionId),
	)

	// Create session resumer and handle the resumption
	resumer := NewSessionResumer(
		s.storage,
		s.sessionManager,
		s.attester,
		s.resumptionConfig.MaxSessionAge,
	)

	// Look up the session
	state, err := s.sessionManager.LoadSessionByPublicKey(req.RemotePublicKey)
	if err != nil {
		slog.Warn("session not found for reconnection",
			slog.Any("error", err),
		)
		return s.sendReconnectReject(cn, "session not found")
	}

	// Verify session ID matches
	if state.SessionID != req.SessionId {
		return s.sendReconnectReject(cn, "session ID mismatch")
	}

	// Verify the session is in a resumable state
	if state.Phase != PhaseEstablished {
		return s.sendReconnectReject(cn, "session not established")
	}

	// Verify the session is not too old
	// Note: We'd need to track creation time in SessionState for this
	// For now, just check that we have a valid shared secret
	if len(state.SharedSecret) == 0 {
		return s.sendReconnectReject(cn, "session state invalid")
	}

	// Generate server challenge
	serverChallenge := randomBytes(resumeChallengeSize)

	// Compute response to client's challenge using HMAC
	challengeResponse := resumer.computeChallengeResponse(req.ResumeChallenge, state.SharedSecret)

	// Send accept response
	resp := &pb.ReconnectResponse{
		Accepted:           true,
		ResumeFromPhase:    state.Phase.ToProto(),
		ChallengeResponse:  challengeResponse,
		ServerChallenge:    serverChallenge,
		ServerSendSequence: state.SendSequence,
		ServerRecvSequence: state.RecvSequence,
	}

	if err := s.sendSignedMessage(cn, resp, RouteReconnect); err != nil {
		return fmt.Errorf("sending accept response: %w", err)
	}

	// Receive client verification
	verifyPayload, err := cn.ReadBytes()
	if err != nil {
		return fmt.Errorf("reading verification: %w", err)
	}

	var verifyST pb.SignedTransport
	if err := proto.Unmarshal(verifyPayload, &verifyST); err != nil {
		return fmt.Errorf("unmarshaling verification transport: %w", err)
	}

	// Verify signature
	if !s.algorithm.Identitfier().Verify(remoteKey, verifyST.Data, verifyST.Signature) {
		return fmt.Errorf("verification signature invalid")
	}

	var verify pb.ReconnectVerify
	if err := proto.Unmarshal(verifyST.Data, &verify); err != nil {
		return fmt.Errorf("unmarshaling verification: %w", err)
	}

	// Verify client's response to our challenge
	expectedClientResponse := resumer.computeChallengeResponse(serverChallenge, state.SharedSecret)
	if len(verify.ChallengeResponse) == 0 || !hmacEqual(verify.ChallengeResponse, expectedClientResponse) {
		complete := &pb.ReconnectComplete{
			Success:      false,
			ErrorMessage: "challenge verification failed",
		}
		_ = s.sendSignedMessage(cn, complete, RouteReconnect)
		return ErrChallengeVerifyFailed
	}

	// Determine sequence numbers to resume from
	resumeSendSeq, resumeRecvSeq := resumer.reconcileSequences(
		state.SendSequence, state.RecvSequence,
		req.LastRecvSequence, req.LastSendSequence,
	)

	// Send completion
	complete := &pb.ReconnectComplete{
		Success:            true,
		ResumeSendSequence: resumeSendSeq,
		ResumeRecvSequence: resumeRecvSeq,
	}
	if err := s.sendSignedMessage(cn, complete, RouteReconnect); err != nil {
		return fmt.Errorf("sending completion: %w", err)
	}

	// Restore the transport
	t, err := resumer.restoreTransport(cn, state, resumeSendSeq, resumeRecvSeq)
	if err != nil {
		return fmt.Errorf("restoring transport: %w", err)
	}

	slog.Info("session resumed",
		slog.String("session_id", t.SessionID()),
		slog.Uint64("send_seq", resumeSendSeq),
		slog.Uint64("recv_seq", resumeRecvSeq),
	)

	// Update session state
	if s.resumptionConfig.PersistSessions {
		if err := SaveSessionForResumption(t, s.sessionManager); err != nil {
			slog.Warn("failed to update session after resumption",
				slog.Any("error", err),
			)
		}
	}

	if err := s.handlerFunc(t); err != nil {
		return fmt.Errorf("handler: %w", err)
	}

	return nil
}

func (s *Server) sendReconnectReject(cn Conn, reason string) error {
	resp := &pb.ReconnectResponse{
		Accepted:     false,
		ErrorMessage: reason,
	}
	if err := s.sendSignedMessage(cn, resp, RouteReconnect); err != nil {
		return fmt.Errorf("sending reject: %w", err)
	}
	return fmt.Errorf("reconnection rejected: %s", reason)
}

func (s *Server) sendSignedMessage(cn Conn, msg Transferable, route Route) error {
	data, err := proto.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshaling message: %w", err)
	}

	sig, err := s.attester.Sign(data)
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

	return cn.WriteBytes(payload)
}

// hmacEqual performs a constant-time comparison of two byte slices.
func hmacEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	result := byte(0)
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// PublicKey returns the server's public key.
func (s *Server) PublicKey() PublicKey {
	return s.attester.PublicKey()
}

// SessionManager returns the server's session manager.
func (s *Server) SessionManager() *SessionManager {
	return s.sessionManager
}

// NewServer creates a new server with the given address and handler.
func NewServer(
	addr string, handler HandlerFunc, opts ...ServerOptions,
) (*Server, error) {
	s := &Server{
		addr:             addr,
		connType:         tcp,
		algorithm:        attest.Ed25519Algorithm,
		handlerFunc:      handler,
		resumptionConfig: DefaultResumptionConfig(),
		handshakeOpts: handshakeOpts{
			ratchetThreshold: defaultRatchetThreshold,
			remoteVerifier:   defaultRemoteVerifier,
		},
	}

	for _, o := range opts {
		o(s)
	}

	storage, err := OpenStorage(s.storageOpts...)
	if err != nil {
		return nil, fmt.Errorf("opening storage: %w", err)
	}

	at, err := storage.attester()
	if err != nil {
		return nil, fmt.Errorf("loading attester: %w", err)
	}

	s.storage = storage
	s.attester = at

	// Initialize session manager for resumption
	s.sessionManager = NewSessionManager(storage, s.resumptionConfig.MaxSessionAge)

	sum := sha256.Sum256(at.PublicKey().Marshal())
	s.serverName = fingerprint.Base64(sum[:])

	return s, nil
}

// ServerOptions configures the server.
type ServerOptions func(*Server)

// ServeWithRemoteVerifier sets a custom remote verifier function.
func ServeWithRemoteVerifier(remote RemoteVerifier) ServerOptions {
	return func(s *Server) { s.handshakeOpts.remoteVerifier = remote }
}

// ServeWithTCP configures the server to use TCP connections.
func ServeWithTCP(opts ...ConnOption) ServerOptions {
	return func(s *Server) { s.connType = tcp; s.connOpts = opts }
}

// ServeWithName sets the server's advertised name.
func ServeWithName(name string) ServerOptions {
	return func(s *Server) { s.serverName = name }
}

// ServeWithAlgorithm sets the cryptographic algorithm for identity.
func ServeWithAlgorithm(a attest.Algorithm) ServerOptions {
	return func(s *Server) { s.algorithm = a }
}

// ServeWithUDP configures the server to use UDP/KCP connections.
func ServeWithUDP(opts ...ConnOption) ServerOptions {
	return func(s *Server) { s.connType = udp; s.connOpts = opts }
}

// ServeWithStorageOpts sets storage options.
func ServeWithStorageOpts(opts ...StorageOption) ServerOptions {
	return func(s *Server) { s.storageOpts = opts }
}

// ServeWithRatchetThreshold sets the message threshold for DH ratchet rotation.
func ServeWithRatchetThreshold(threshold uint64) ServerOptions {
	return func(s *Server) { s.handshakeOpts.ratchetThreshold = threshold }
}

// ServeWithResumption configures session resumption settings.
func ServeWithResumption(config ResumptionConfig) ServerOptions {
	return func(s *Server) { s.resumptionConfig = config }
}

// ServeWithResumptionEnabled enables or disables session resumption.
func ServeWithResumptionEnabled(enabled bool) ServerOptions {
	return func(s *Server) { s.resumptionConfig.Enabled = enabled }
}

// ServeWithSessionTimeout sets the maximum age for resumable sessions.
func ServeWithSessionTimeout(timeout time.Duration) ServerOptions {
	return func(s *Server) { s.resumptionConfig.MaxSessionAge = timeout }
}
