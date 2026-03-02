package kamune

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"
	"sync"
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
	listener         net.Listener
	handshakeOpts    handshakeOpts
	sessionManager   *SessionManager
	handlerFunc      HandlerFunc
	storage          *Storage
	addr             string
	serverName       string
	connOpts         []ConnOption
	storageOpts      []StorageOption
	resumptionConfig ResumptionConfig
	algorithm        attest.Algorithm
	connType         connType
	mu               sync.Mutex
}

// ListenAndServe starts the server and listens for incoming connections.
// It blocks until the listener is closed via [Server.Close] or an
// unrecoverable error occurs.
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

	s.mu.Lock()
	s.listener = l
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.listener = nil
		s.mu.Unlock()

		if err := l.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
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

// Close gracefully shuts down the server by closing the underlying listener,
// causing [Server.ListenAndServe] to return. It is safe to call multiple
// times and concurrently.
func (s *Server) Close() error {
	s.mu.Lock()
	l := s.listener
	s.listener = nil
	s.mu.Unlock()

	if l == nil {
		return nil
	}
	return l.Close()
}

func (s *Server) listen() (net.Listener, error) {
	switch s.connType {
	case tcp:
		return net.Listen("tcp", s.addr)
	case udp:
		return kcp.Listen(s.addr)
	default:
		return nil, fmt.Errorf("unknown conn type: %v", s.connType)
	}
}

func (s *Server) handleConnection(c net.Conn) {
	cn, err := newConn(c, s.connOpts...)
	if err != nil {
		slog.Error("new conn", slog.Any("error", err))
		return
	}

	if err := s.serve(cn); err != nil {
		slog.Error(
			"serve conn",
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
	case RouteIdentity:
		return s.handleNewConnection(cn, st)
	case RouteReconnect:
		return s.handleReconnection(cn, st)
	default:
		return fmt.Errorf(
			"%w: expected %s or %s, got %s",
			ErrUnexpectedRoute,
			RouteIdentity,
			RouteReconnect,
			route,
		)
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

	err = sendIntroduction(cn, s.serverName, s.attester, s.algorithm)
	if err != nil {
		return fmt.Errorf("sending introduction: %w", err)
	}

	pt := newPlainTransport(cn, peer.PublicKey, s.attester, s.storage)
	t, err := acceptHandshake(pt, s.handshakeOpts)
	if err != nil {
		return fmt.Errorf("accepting handshake: %w", err)
	}

	slog.Info(
		"session established",
		slog.String("session_id", t.SessionID()),
		slog.String("peer", peer.Name),
	)

	// Save session for potential resumption
	if s.resumptionConfig.Enabled && s.resumptionConfig.PersistSessions {
		if err := SaveSessionForResumption(t, s.sessionManager); err != nil {
			slog.Warn(
				"failed to save session for resumption",
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
		return s.sendReconnectReject(cn, "resumption failed")
	}

	// Parse the reconnect request from the signed transport.
	var req pb.ReconnectRequest
	if err := proto.Unmarshal(st.Data, &req); err != nil {
		return fmt.Errorf("unmarshaling reconnect request: %w", err)
	}

	// Verify the signature using the claimed public key before handing off
	// to the resumer, which trusts the request is authentic.
	remoteKey, err := s.algorithm.Identitfier().ParsePublicKey(
		req.RemotePublicKey,
	)
	if err != nil {
		return s.sendReconnectReject(cn, "resumption failed")
	}

	if !s.algorithm.Identitfier().Verify(remoteKey, st.Data, st.Signature) {
		return s.sendReconnectReject(cn, "resumption failed")
	}

	slog.Info("reconnection request received",
		slog.String("session_id", req.SessionId),
	)

	// Delegate the entire challenge-response protocol to SessionResumer.
	resumer := NewSessionResumer(
		s.storage,
		s.sessionManager,
		s.attester,
		s.resumptionConfig.MaxSessionAge,
	)

	t, err := resumer.HandleResumption(cn, &req)
	if err != nil {
		return fmt.Errorf("handling resumption: %w", err)
	}

	slog.Info("session resumed",
		slog.String("session_id", t.SessionID()),
	)

	// Update session state.
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
	// Always send a generic rejection reason on the wire to reduce information
	// leakage / session enumeration. The provided `reason` is used only for logs.
	resp := &pb.ReconnectResponse{
		Accepted:     false,
		ErrorMessage: "resumption failed",
	}
	if err := s.sendSignedMessage(cn, resp, RouteReconnect); err != nil {
		return fmt.Errorf("sending reject: %w", err)
	}

	// Avoid returning an error that includes the specific rejection reason.
	// Callers can log `reason` explicitly if needed.
	return fmt.Errorf("reconnection rejected")
}

func (s *Server) sendSignedMessage(
	cn Conn, msg Transferable, route Route,
) error {
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
			remoteVerifier: defaultRemoteVerifier,
			timeout:        30 * time.Second,
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
	s.serverName = fingerprint.Sum(at.PublicKey().Marshal())

	// Initialize session manager for resumption
	s.sessionManager = NewSessionManager(
		storage, s.resumptionConfig.MaxSessionAge,
	)

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
