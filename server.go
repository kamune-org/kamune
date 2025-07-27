package kamune

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/hossein1376/kamune/internal/attest"
)

type HandlerFunc func(t *Transport) error

type Server struct {
	addr           string
	handlerFunc    HandlerFunc
	remoteVerifier RemoteVerifier
	attest         *attest.Attest
}

func (s *Server) ListenAndServe() error {
	l, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", s.addr, err)
	}
	defer l.Close()
	return s.Serve(l)
}

func (s *Server) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			s.log(slog.LevelError, "accept conn", slog.Any("err", err))
			continue
		}
		go func() {
			if err := s.serve(conn); err != nil {
				s.log(slog.LevelWarn, "serve conn", slog.Any("err", err))
				return
			}
		}()
	}
}

func (s *Server) serve(c net.Conn) error {
	conn := Conn{Conn: c}
	defer func() {
		if err := recover(); err != nil {
			s.log(slog.LevelError, "serve panic", slog.Any("err", err))
		}
		if !conn.isClosed {
			if err := conn.Close(); err != nil {
				s.log(slog.LevelError, "close conn", slog.Any("err", err))
			}
		}
	}()

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

func (s *Server) log(lvl slog.Level, msg string, args ...any) {
	slog.Log(context.Background(), lvl, msg, args...)
}

func NewServer(
	addr string, handler HandlerFunc, opts ...ServerOptions,
) (*Server, error) {
	at, err := attest.LoadFromDisk(privKeyPath)
	if err != nil {
		return nil, fmt.Errorf("loading identity: %w", err)
	}

	s := &Server{attest: at, addr: addr, handlerFunc: handler}
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
