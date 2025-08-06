package kamune

import (
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/xtaci/kcp-go/v5"

	"github.com/hossein1376/kamune/pkg/attest"
)

type HandlerFunc func(t *Transport) error

type Server struct {
	addr           string
	connType       connType
	handlerFunc    HandlerFunc
	remoteVerifier RemoteVerifier
	attest         attest.Attest
	connOpts       []ConnOption
}

func (s *Server) ListenAndServe() error {
	l, err := s.listen()
	if err != nil {
		return fmt.Errorf("listening: %w", err)
	}
	defer l.Close()

	for {
		c, err := l.Accept()
		if err != nil {
			slog.Error("accept conn", slog.Any("err", err))
			continue
		}
		go func() {
			conn, err := newConn(c, s.connOpts...)
			if err != nil {
				slog.Error("new tcp conn", slog.Any("err", err))
				return
			}
			err = s.serve(conn)
			if err != nil {
				slog.Error("serve conn", slog.Any("err", err))
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
		if err := recover(); err != nil {
			slog.Error("serve panic", slog.Any("err", err))
		}
		err := conn.Close()
		if err != nil && !errors.Is(err, ErrConnClosed) {
			slog.Error("close conn", slog.Any("err", err))
		}
	}()

	// TODO(h.yazdani): support multiple routes

	remote, err := receiveIntroduction(conn)
	if err != nil {
		return fmt.Errorf("receive introduction: %w", err)
	}
	if err := s.remoteVerifier(remote); err != nil {
		return fmt.Errorf("verify remote: %w", err)
	}
	if err := sendIntroduction(conn, s.attest); err != nil {
		return fmt.Errorf("send introduction: %w", err)
	}

	pt := &plainTransport{conn: conn, remote: remote, attest: s.attest}
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
	at, err := attest.LoadFromDisk(privKeyPath)
	if err != nil {
		return nil, fmt.Errorf("loading identity: %w", err)
	}

	s := &Server{
		addr:        addr,
		connType:    tcp,
		attest:      at,
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
