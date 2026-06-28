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
	"github.com/kamune-org/kamune/pkg/exchange"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
)

// Listener accepts incoming connections as [Conn] values. Unlike net.Listener
// (which yields net.Conn), this yields the abstract Conn interface, suitable
// for custom transport backends such as a relay WebSocket.
type Listener interface {
	Accept() (Conn, error)
	Close() error
}

// Server handles incoming connections and manages the handshake process.
type Server struct {
	listener      Listener
	attest        *attest.Attest
	storage       *storage.Storage
	serverName    string
	handlerFunc   HandlerFunc
	handshakeOpts handshakeOpts
	addr          string
	connOpts      []ConnOption
	closed        bool
	mu            sync.Mutex
}

// ListenAndServe starts the server and listens for incoming connections.
// It blocks until the listener is closed via [Server.Close] or an
// unrecoverable error occurs.
func (s *Server) ListenAndServe() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosedServer
	}
	if s.listener == nil {
		// defaults to TCP
		l, err := net.Listen("tcp", s.addr)
		if err != nil {
			s.mu.Unlock()
			return fmt.Errorf("listening tcp: %w", err)
		}
		s.listener = &tcpListener{Listener: l, connOpts: s.connOpts}
	}
	s.mu.Unlock()

	slog.Info("server started", slog.String("addr", s.addr))

	for {
		cn, err := s.listener.Accept()
		if err != nil {
			// Exit cleanly when the listener is closed (shutdown).
			if errors.Is(err, net.ErrClosed) {
				return nil
			}

			slog.Error("accept conn", slog.Any("error", err))
			continue
		}
		go func() {
			if err := s.serve(cn); err != nil {
				slog.Error("serve conn", slog.Any("error", err))
			}
		}()
	}
}

// Close gracefully shuts down the server by closing the underlying listener,
// causing [Server.ListenAndServe] to return. It is safe to call multiple
// times and concurrently.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	if s.listener != nil {
		_ = s.listener.Close()
	}

	s.closed = true
	return nil
}

// tcpListener wraps a net.Listener and yields *conn values.
type tcpListener struct {
	net.Listener
	connOpts []ConnOption
}

func (l *tcpListener) Accept() (Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return newConn(c, l.connOpts...), nil
}

// udpListener wraps a KCP listener and yields *conn values.
type udpListener struct {
	net.Listener
	connOpts []ConnOption
}

func (l *udpListener) Accept() (Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return newConn(c, l.connOpts...), nil
}

func (s *Server) serve(cn Conn) (err error) {
	defer func() {
		if msg := recover(); msg != nil {
			slog.Error(
				"handshake serve panic",
				slog.Any("message", msg),
				slog.String("stack", string(debug.Stack())),
			)
			err = fmt.Errorf("serve panic: %v", msg)
		}
		if err := cn.Close(); err != nil && !errors.Is(err, ErrConnClosed) {
			slog.Error("close conn", slog.Any("err", err))
		}
	}()

	// Step 0: Exchange HPKE keys to derive an encrypted connection for the
	// handshake
	ec, err := exchange.Accept(cn)
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
	cn Conn, ec *exchange.Channel, st *pb.SignedTransport,
) error {
	// Bound the handshake to avoid indefinite blocking.
	_ = cn.SetDeadline(time.Now().Add(s.handshakeOpts.timeout))
	defer func() { _ = cn.SetDeadline(time.Time{}) }()

	peer, remoteVersion, err := receiveIntroduction(st)
	if err != nil {
		return fmt.Errorf("receiving introduction: %w", err)
	}

	if err := checkVersion(remoteVersion); err != nil {
		return fmt.Errorf("version check: %w", err)
	}

	if err := s.handshakeOpts.remoteVerifier(s.storage, peer); err != nil {
		return fmt.Errorf("verify remote: %w", err)
	}

	err = sendIntroduction(ec, s.attest, s.serverName, AppVersion)
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
	t.remotePeer = peer

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

// NewServer creates a new server with the given address, handler, and storage.
// By default the server uses TCP on the given address when [Server.ListenAndServe]
// is called, unless a different listener or transport is configured via options.
func NewServer(
	addr string,
	handler HandlerFunc,
	store *storage.Storage,
	opts ...ServerOptions,
) (*Server, error) {
	s := &Server{
		addr:        addr,
		storage:     store,
		handlerFunc: handler,
		handshakeOpts: handshakeOpts{
			remoteVerifier: defaultRemoteVerifier,
			timeout:        30 * time.Second,
		},
	}

	for _, o := range opts {
		if err := o(s); err != nil {
			return nil, err
		}
	}

	at, err := s.storage.Attester()
	if err != nil {
		return nil, fmt.Errorf("loading attester: %w", err)
	}

	s.attest = at
	if s.serverName == "" {
		s.serverName = fingerprint.Sum(at.MarshalPublicKey())
	}
	return s, nil
}

// ServerOptions configures the server. Returning an error from an option
// causes [NewServer] to fail immediately with that error.
type ServerOptions func(*Server) error

// ServeWithRemoteVerifier sets a custom remote verifier function.
func ServeWithRemoteVerifier(remote RemoteVerifier) ServerOptions {
	return func(s *Server) error {
		s.handshakeOpts.remoteVerifier = remote
		return nil
	}
}

// ServeWithServerName sets the server's advertised name.
func ServeWithServerName(name string) ServerOptions {
	return func(s *Server) error {
		s.serverName = name
		return nil
	}
}

// ServeWithTCP configures the server to use TCP connections with the given
// connection options. If not called, TCP with default options is used.
func ServeWithTCP(opts ...ConnOption) ServerOptions {
	return func(s *Server) error {
		s.connOpts = opts
		l, err := net.Listen("tcp", s.addr)
		if err != nil {
			return fmt.Errorf("listening tcp: %w", err)
		}
		s.listener = &tcpListener{Listener: l, connOpts: opts}
		return nil
	}
}

// ServeWithUDP configures the server to use UDP/KCP connections.
func ServeWithUDP(opts ...ConnOption) ServerOptions {
	return func(s *Server) error {
		s.connOpts = opts
		l, err := kcp.Listen(s.addr)
		if err != nil {
			return fmt.Errorf("listening udp: %w", err)
		}
		s.listener = &udpListener{Listener: l, connOpts: opts}
		return nil
	}
}

// ServeWithListener uses the caller-provided Listener directly. The addr
// argument passed to [NewServer] is unused in this case; pass "".
func ServeWithListener(l Listener) ServerOptions {
	return func(s *Server) error {
		s.listener = l
		return nil
	}
}
