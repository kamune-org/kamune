package kamune

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"

	"github.com/xtaci/kcp-go/v5"

	"github.com/kamune-org/kamune/internal/enigma"
	"github.com/kamune-org/kamune/pkg/attest"
)

type Server struct {
	addr           string
	serverName     string
	attester       attest.Attester
	identity       attest.Identity
	storage        *Storage
	connType       connType
	handlerFunc    HandlerFunc
	remoteVerifier RemoteVerifier
	connOpts       []ConnOption
	storageOpts    []StorageOption
}

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

	for {
		c, err := l.Accept()
		if err != nil {
			slog.Error("accept conn", slog.Any("error", err))
			continue
		}
		go func() {
			conn, err := newConn(c, s.connOpts...)
			if err != nil {
				slog.Error("new tcp conn", slog.Any("error", err))
				return
			}
			err = s.serve(conn)
			if err != nil {
				slog.Error("serve conn", slog.Any("error", err))
			}
		}()
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

func (s *Server) serve(conn *Conn) error {
	defer func() {
		if msg := recover(); msg != nil {
			slog.Error(
				"serve panic",
				slog.Any("message", msg),
				slog.String("stack", string(debug.Stack())),
			)
		}
		err := conn.Close()
		if err != nil && !errors.Is(err, ErrConnClosed) {
			slog.Error("close conn", slog.Any("err", err))
		}
	}()

	// TODO(h.yazdani): support multiple routes

	peer, err := receiveIntroduction(conn)
	if err != nil {
		return fmt.Errorf("receive introduction: %w", err)
	}
	if err := s.remoteVerifier(s.storage, peer); err != nil {
		return fmt.Errorf("verify remote: %w", err)
	}
	err = sendIntroduction(conn, s.serverName, s.attester, s.identity)
	if err != nil {
		return fmt.Errorf("send introduction: %w", err)
	}

	pt := newPlainTransport(conn, peer.PublicKey, s.attester, s.storage.identity)
	t, err := acceptHandshake(pt)
	if err != nil {
		return fmt.Errorf("accept handshake: %w", err)
	}
	err = s.handlerFunc(t)
	if err != nil {
		return fmt.Errorf("handler: %w", err)
	}

	return nil
}

func NewServer(
	addr string, handler HandlerFunc, opts ...ServerOptions,
) (*Server, error) {
	s := &Server{
		addr:        addr,
		connType:    tcp,
		serverName:  enigma.Text(10),
		identity:    attest.Ed25519,
		handlerFunc: handler,
	}
	for _, o := range opts {
		if err := o(s); err != nil {
			return nil, fmt.Errorf("applying options: %w", err)
		}
	}
	if s.remoteVerifier == nil {
		s.remoteVerifier = defaultRemoteVerifier
	}

	storage, err := openStorage(s.storageOpts...)
	if err != nil {
		return nil, fmt.Errorf("opening storage: %w", err)
	}
	at, err := storage.attester()
	if err != nil {
		return nil, fmt.Errorf("loading attester: %w", err)
	}
	s.storage = storage
	s.attester = at

	return s, nil
}

type ServerOptions func(*Server) error

func ServeWithRemoteVerifier(remote RemoteVerifier) ServerOptions {
	return func(s *Server) error {
		if s.remoteVerifier != nil {
			return errors.New("server already has a remote verifier")
		}
		s.remoteVerifier = remote
		return nil
	}
}

func ServeWithTCP(opts ...ConnOption) ServerOptions {
	return func(s *Server) error {
		if s.connOpts != nil {
			return errors.New("server already has a conn opts")
		}
		s.connType = tcp
		s.connOpts = opts
		return nil
	}
}

func ServeWithName(name string) ServerOptions {
	return func(s *Server) error {
		s.serverName = name
		return nil
	}
}

func ServeWithIdentity(id attest.Identity) ServerOptions {
	return func(s *Server) error {
		s.identity = id
		return nil
	}
}

func ServeWithUDP(opts ...ConnOption) ServerOptions {
	return func(s *Server) error {
		if s.connOpts != nil {
			return errors.New("server already has a conn opts")
		}
		s.connType = udp
		s.connOpts = opts
		return nil
	}
}

func ServeWithStorageOpts(opts ...StorageOption) ServerOptions {
	return func(s *Server) error {
		s.storageOpts = opts
		return nil
	}
}
