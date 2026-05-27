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

	"github.com/kamune-org/kamune/internal/box/pb"
	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
)

// Server handles incoming connections and manages the handshake process.
type Server struct {
	listener      net.Listener
	attest        *attest.Attest
	storage       *storage.Storage
	handlerFunc   HandlerFunc
	handshakeOpts handshakeOpts
	addr          string
	serverName    string
	connOpts      []ConnOption
	storageOpts   []storage.StorageOption
	connType      connType
	mu            sync.Mutex
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
	case tcpConn:
		return net.Listen("tcp", s.addr)
	case udpConn:
		return kcp.Listen(s.addr)
	default:
		return nil, fmt.Errorf("unknown conn type: %v", s.connType)
	}
}

func (s *Server) handleConnection(c net.Conn) {
	if err := s.serve(newConn(c, s.connOpts...)); err != nil {
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
				"handshake serve panic",
				slog.Any("message", msg),
				slog.String("stack", string(debug.Stack())),
			)
		}
		if err := cn.Close(); err != nil && !errors.Is(err, ErrConnClosed) {
			slog.Error("close conn", slog.Any("err", err))
		}
	}()

	// Step 0: Exchange HPKE keys to derive an encrypted connection for the
	// handshake
	ec, err := acceptExchange(cn)
	if err != nil {
		return fmt.Errorf("accepting exchange: %w", err)
	}

	// Step 1: Receive introduction
	st, err := readSignedTransport(ec)
	if err != nil {
		return fmt.Errorf("reading transport: %w", err)
	}

	// Handle different routes at this stage
	switch route := RouteFromProto(st.GetMetadata().GetRoute()); route {
	case RouteIdentity:
		return s.handleNewConnection(cn, ec, st)
	default:
		return fmt.Errorf(
			"%w: expected %s, got %s",
			ErrUnexpectedRoute,
			RouteIdentity,
			route,
		)
	}
}

func (s *Server) handleNewConnection(
	cn Conn, ec *encryptedConn, st *pb.SignedTransport,
) error {
	// Bound the handshake to avoid indefinite blocking.
	_ = cn.SetDeadline(time.Now().Add(s.handshakeOpts.timeout))
	defer func() { _ = cn.SetDeadline(time.Time{}) }()

	peer, err := receiveIntroduction(st)
	if err != nil {
		return fmt.Errorf("receiving introduction: %w", err)
	}

	if err := s.handshakeOpts.remoteVerifier(s.storage, peer); err != nil {
		return fmt.Errorf("verify remote: %w", err)
	}

	err = sendIntroduction(ec, s.serverName, s.attest)
	if err != nil {
		return fmt.Errorf("sending introduction: %w", err)
	}

	serde := newSignedSerde(peer.PublicKey, s.attest)
	t, err := acceptHandshake(ec, serde, s.handshakeOpts)
	if err != nil {
		return fmt.Errorf("accepting handshake: %w", err)
	}
	// Since from now on all communications are encrypted via the newly ciphers
	// derived from the handshake, we can switch to the plain connection.
	t.conn = cn
	t.store = s.storage

	slog.Info(
		"session established",
		slog.String("session_id", t.SessionID()),
		slog.String("peer", peer.Name),
	)

	if err := s.handlerFunc(t); err != nil {
		return fmt.Errorf("handler: %w", err)
	}

	return nil
}

// PublicKey returns the server's public key.
func (s *Server) PublicKey() []byte {
	return s.attest.MarshalPublicKey()
}

// NewServer creates a new server with the given address and handler.
func NewServer(
	addr string, handler HandlerFunc, opts ...ServerOptions,
) (*Server, error) {
	s := &Server{
		addr:        addr,
		connType:    tcpConn,
		handlerFunc: handler,
		handshakeOpts: handshakeOpts{
			remoteVerifier: defaultRemoteVerifier,
			timeout:        30 * time.Second,
		},
	}

	for _, o := range opts {
		o(s)
	}

	storage, err := storage.OpenStorage(s.storageOpts...)
	if err != nil {
		return nil, fmt.Errorf("opening storage: %w", err)
	}

	at, err := storage.Attester()
	if err != nil {
		return nil, fmt.Errorf("loading attester: %w", err)
	}

	s.storage = storage
	s.attest = at
	s.serverName = fingerprint.Sum(at.MarshalPublicKey())

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
	return func(s *Server) { s.connType = tcpConn; s.connOpts = opts }
}

// ServeWithName sets the server's advertised name.
func ServeWithName(name string) ServerOptions {
	return func(s *Server) { s.serverName = name }
}

// ServeWithUDP configures the server to use UDP/KCP connections.
func ServeWithUDP(opts ...ConnOption) ServerOptions {
	return func(s *Server) { s.connType = udpConn; s.connOpts = opts }
}

// ServeWithStorageOpts sets storage options.
func ServeWithStorageOpts(opts ...storage.StorageOption) ServerOptions {
	return func(s *Server) { s.storageOpts = opts }
}
