package kamune

import (
	"crypto/hpke"
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
	"github.com/kamune-org/kamune/pkg/storage"
)

// Server handles incoming connections and manages the handshake process.
type Server struct {
	attester      attest.Attester
	listener      net.Listener
	handshakeOpts handshakeOpts
	handlerFunc   HandlerFunc
	storage       *storage.Storage
	addr          string
	serverName    string
	connOpts      []ConnOption
	storageOpts   []storage.StorageOption
	algorithm     attest.Algorithm
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

	// Step 0: Exchange HPKE keys to derive an encrypted connection for the
	// handshake
	ec, err := acceptExchange(cn)
	if err != nil {
		return fmt.Errorf("accepting exchange: %w", err)
	}

	// Step 1: Receive introduction with route validation
	st, route, err := readSignedTransport(ec)
	if err != nil {
		return fmt.Errorf("reading transport: %w", err)
	}

	// Handle different routes at this stage
	switch route {
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

func acceptExchange(c Conn) (*encryptedConn, error) {
	kem := hpkeKEM()
	kdf := hpkeKDF()
	aead := hpkeAEAD()

	remotePubBytes, err := c.ReadBytes()
	if err != nil {
		return nil, fmt.Errorf("reading remote public key: %w", err)
	}
	remotePub, err := kem.NewPublicKey(remotePubBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing remote public key: %w", err)
	}
	enc, sender, err := hpke.NewSender(remotePub, kdf, aead, nil)
	if err != nil {
		return nil, fmt.Errorf("creating sender: %w", err)
	}
	if err := c.WriteBytes(enc); err != nil {
		return nil, fmt.Errorf("writing ciphertext: %w", err)
	}

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

	return newEncryptedConn(c, sender, recipient), nil
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

	err = sendIntroduction(ec, s.serverName, s.attester, s.algorithm)
	if err != nil {
		return fmt.Errorf("sending introduction: %w", err)
	}

	pt := newUnderlyingTransport(cn, ec, peer.PublicKey, s.attester, s.storage)
	t, err := acceptHandshake(pt, s.handshakeOpts)
	if err != nil {
		return fmt.Errorf("accepting handshake: %w", err)
	}

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

// NewServer creates a new server with the given address and handler.
func NewServer(
	addr string, handler HandlerFunc, opts ...ServerOptions,
) (*Server, error) {
	s := &Server{
		addr:        addr,
		connType:    tcp,
		algorithm:   attest.Ed25519Algorithm,
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
	s.attester = at
	s.serverName = fingerprint.Sum(at.PublicKey().Marshal())

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
func ServeWithStorageOpts(opts ...storage.StorageOption) ServerOptions {
	return func(s *Server) { s.storageOpts = opts }
}
