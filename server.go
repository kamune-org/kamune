package kamune

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"runtime/debug"
	"sync"
	"time"

	"github.com/kamune-org/kamune/internal/admit"
	"github.com/kamune-org/kamune/internal/clock"
	"github.com/kamune-org/kamune/pkg/attest"
	"github.com/kamune-org/kamune/pkg/fingerprint"
	"github.com/kamune-org/kamune/pkg/storage"
)

// Listener accepts incoming connections as [Conn] values.
type Listener interface {
	Accept() (Conn, error)
	Close() error
}

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

const (
	// defaultMaxPendingHandshakes is how many accepted connections may wait for
	// the dialer's ClientHello at once, unless [ServeWithMaxPendingHandshakes]
	// changes it.
	defaultMaxPendingHandshakes = 256

	// defaultMaxPendingPerSource is how many connections from one source may
	// be in the handshake at once, unless [ServeWithMaxPendingPerSource]
	// changes it.
	defaultMaxPendingPerSource = 16

	// defaultIntroTimeout is how long an accepted connection has to send
	// ClientHello, unless [ServeWithIntroTimeout] changes it.
	defaultIntroTimeout = 10 * time.Second

	// minAcceptDelay and maxAcceptDelay bound how long ListenAndServe waits
	// after an Accept error before it calls Accept again. The wait doubles on
	// each consecutive error.
	minAcceptDelay = 5 * time.Millisecond
	maxAcceptDelay = time.Second

	// sweepInterval is how often a persistence server sweeps resumption rows.
	// The timestamp comes from the server clock; the wait is wall time, because
	// [clock.Clock] has no ticker.
	sweepInterval = time.Hour
)

// Server handles incoming connections and manages the handshake process.
type Server struct {
	listener    Listener
	clock       clock.Clock
	attest      *attest.Attest
	storage     *storage.Storage
	handlerFunc HandlerFunc
	listen      func() (Listener, error)
	ctx         context.Context
	cancel      context.CancelFunc
	done        chan struct{}
	// sources counts the connections from each source that are in the
	// handshake, for the per-source cap.
	sources map[string]int
	pending map[*pendingConn]struct{}
	// waiting and hello are the two pre-authentication stages. Each is capped
	// by maxPending. A ClientHello flood can evict only hello.
	waiting       stage
	hello         stage
	serverName    string
	version       string
	addr          string
	connOpts      []ConnOption
	handshakeOpts handshakeOpts
	introTimeout  time.Duration
	maxPending    int
	maxPerSource  int
	wg            sync.WaitGroup
	mu            sync.Mutex
	resumeEnabled bool
	sweepStarted  bool
	closed        bool
}

// pendingConn is a connection accepted by ListenAndServe whose handshake has
// not ended yet.
type pendingConn struct {
	conn Conn
	// source is the key under which the per-source cap counts the connection,
	// or "" when that cap does not apply to it.
	source string
	// network is the key under which the connection counts while it is on
	// waiting or hello.
	network string
	// where is the pre-authentication list p is on, or admitNone.
	where admitPlace // guarded by Server.mu
	// forgeable is whether the connection's source address can be forged,
	// that is, the connection is not return-routable (see isReturnRoutable).
	// The per-source cap then counts it only once the dialer has
	// authenticated, which needs the server's reply.
	forgeable bool
	// counted is whether the per-source cap counts the connection.
	counted bool // guarded by Server.mu
	// authenticated is whether sig_I and finished_I have verified.
	authenticated bool // guarded by Server.mu
	// dropped is whether the server closed the connection to make room for a
	// newer one before the dialer authenticated.
	dropped bool // guarded by Server.mu
	ended   bool // guarded by Server.mu
}

// ListenAndServe starts the server and listens for incoming connections. It
// blocks until the listener is closed via [Server.Close] or an unrecoverable
// error occurs.
//
// Other Accept errors, such as running out of file descriptors, are logged and
// retried after a wait that starts at 5 ms and doubles up to 1 s.
//
// By default an accepted connection has 10 seconds to send ClientHello, and at
// most 256 connections may wait for that at once. The same cap applies again
// after ClientHello, until the dialer authenticates.
// ListenAndServe keeps accepting at that cap: a new connection takes the place
// of a waiting one, which is closed, from the networks that hold the most
// places. Idle connections from fewer networks than the cap thus cannot keep
// out a dialer that sends ClientHello within a few round trips. One source may
// have at most 16 connections in the handshake at once. A connection whose
// source address can be forged, such as a raw UDP or KCP connection that a
// custom [Listener] returns, counts only once its dialer has authenticated.
// TCP connections and the UDP paths of [ServeWithUDP] count from accept. See
// [ServeWithIntroTimeout], [ServeWithMaxPendingHandshakes], and
// [ServeWithMaxPendingPerSource].
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
	s.startSweep()

	slog.Info("server started", slog.String("addr", s.addr))

	var delay time.Duration
	for {
		cn, err := s.listener.Accept()
		if err != nil {
			// Exit cleanly when the listener is closed (shutdown).
			if s.isClosed() || isListenerClosed(err) {
				return nil
			}

			// Errors such as EMFILE repeat until something changes, so wait
			// before trying again instead of spinning.
			delay = nextAcceptDelay(delay)
			slog.Error(
				"accept conn",
				slog.Any("error", err),
				slog.Duration("retry_in", delay),
			)
			if !s.pause(delay) {
				return nil
			}
			continue
		}
		delay = 0

		p, dropped, ok := s.admit(cn)
		if dropped != nil {
			_ = dropped.Close()
		}
		if !ok {
			_ = cn.Close()
			if s.isClosed() {
				return nil
			}
			continue
		}
		go func() {
			defer s.wg.Done()
			err := s.serveConn(cn, p)
			switch {
			case err == nil:
			case s.isClosed():
				slog.Debug("serve conn after close", slog.Any("error", err))
			case !s.wasAuthenticated(p):
				// Anyone can open a connection and let it time out or drop it,
				// so these failures would flood the log.
				slog.Debug(
					"serve conn before authentication",
					slog.Any("error", err),
				)
			default:
				slog.Error("serve conn", slog.Any("error", err))
			}
		}()
	}
}

// admit records cn as being in the handshake, so that Close can close it and
// Shutdown waits for it, and as waiting for ClientHello. It reports false and
// records nothing when the server is closed or when cn's source is at the
// per-source cap.
//
// When the waiting connections are at the cap already, admit drops one of them
// to make room and returns its conn for the caller to close (see
// dropCandidate). A real dialer sends ClientHello within a few round trips, so
// the connections from the networks that hold the most places are the least
// likely to be real dialers.
//
// A connection whose source address may be forged is not checked against the
// per-source cap here: a sender could then use up the places of the host it
// names. authenticated checks it once its dialer has authenticated.
func (s *Server) admit(cn Conn) (*pendingConn, Conn, bool) {
	p := &pendingConn{conn: cn}
	if addr := connAddr(cn); addr != nil {
		p.forgeable = !isReturnRoutable(cn)
		p.source = admit.SourceKey(addr)
		p.network = admit.NetworkKey(addr)
	}
	if s.maxPerSource == 0 {
		p.source = ""
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, nil, false
	}
	if p.source != "" && !p.forgeable && !s.countSourceLocked(p) {
		return nil, nil, false
	}

	var dropped Conn
	if s.maxPending > 0 {
		if s.waiting.len() >= s.maxPending {
			victim := s.waiting.dropCandidate(p.network)
			s.waiting.remove(victim)
			victim.dropped = true
			dropped = victim.conn
			slog.Debug(
				"dropped waiting connection for a newer one",
				slog.String("network", victim.network),
			)
		}
		s.waiting.add(p)
	}
	if s.pending == nil {
		s.pending = make(map[*pendingConn]struct{})
	}
	s.pending[p] = struct{}{}
	s.wg.Add(1)
	return p, dropped, true
}

// countSourceLocked counts p for the per-source cap, or reports false when its
// source is at the cap already.
func (s *Server) countSourceLocked(p *pendingConn) bool {
	if s.sources[p.source] >= s.maxPerSource {
		// Debug, not Warn: a flood from one source would flood the log.
		slog.Debug(
			"too many pending handshakes from source",
			slog.String("source", p.source),
		)
		return false
	}
	if s.sources == nil {
		s.sources = make(map[string]int)
	}
	s.sources[p.source]++
	p.counted = true
	return true
}

// endHandshake marks the handshake of p as over and frees its place among the
// waiting connections, if it still holds one, and in the per-source count. It
// reports whether the server is still open. p may be nil, for a connection that
// ListenAndServe did not accept, and a second call for the same p only reports.
func (s *Server) endHandshake(p *pendingConn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	open := !s.closed
	if p == nil || p.ended {
		return open
	}
	p.ended = true
	s.waiting.remove(p)
	s.hello.remove(p)
	delete(s.pending, p)
	if !p.counted {
		return open
	}
	p.counted = false
	if s.sources[p.source] <= 1 {
		delete(s.sources, p.source)
	} else {
		s.sources[p.source]--
	}
	return open
}

// isListenerClosed reports whether an Accept error means the listener was
// closed. A listener may report that as io.ErrClosedPipe instead of
// net.ErrClosed.
func isListenerClosed(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe)
}

// nextAcceptDelay returns the wait after an Accept error that followed a wait
// of prev.
func nextAcceptDelay(prev time.Duration) time.Duration {
	if prev <= 0 {
		return minAcceptDelay
	}
	return min(2*prev, maxAcceptDelay)
}

// pause waits for d and reports true, or reports false as soon as the server is
// closed.
func (s *Server) pause(d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return !s.isClosed()
	case <-s.done:
		return false
	}
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// connAddr returns cn's remote address, or nil when cn does not report one.
func connAddr(cn Conn) net.Addr {
	ra, ok := cn.(interface{ RemoteAddr() net.Addr })
	if !ok {
		return nil
	}
	return ra.RemoteAddr()
}

// Close shuts the server down. It closes the listener, so that
// [Server.ListenAndServe] returns, and closes the connections that are still in
// the handshake. A handshake that completes after Close is not handed to the
// handler and its session is not stored; its transport is closed instead.
// Sessions already handed to the handler are not affected: close their
// transports to end them. Close does not wait for anything; see
// [Server.Shutdown]. It is safe to call multiple times and concurrently.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}

	// Mark the server closed before closing the listener, so the Accept error
	// that follows is read as shutdown whatever it is.
	s.closed = true
	if s.done != nil {
		close(s.done)
	}
	cancel := s.cancel
	l := s.listener
	pending := make([]Conn, 0, len(s.pending))
	for p := range s.pending {
		pending = append(pending, p.conn)
	}
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}

	if l != nil {
		_ = l.Close()
	}
	for _, cn := range pending {
		_ = cn.Close()
	}
	return nil
}

// Shutdown closes the server as [Server.Close] does, then waits until every
// connection accepted by [Server.ListenAndServe] is done with: its handshake
// has ended and, if it was handed to the handler, the handler has returned.
// Handlers return when their sessions end, so close the sessions' transports
// before or while Shutdown waits. Shutdown returns ctx.Err() if ctx is done
// first. It does not stop the handshakes and handlers still running then: they
// carry on until they return.
func (s *Server) Shutdown(ctx context.Context) error {
	_ = s.Close()
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) serve(cn Conn) error {
	return s.serveConn(cn, nil)
}

// serveConn runs the handshake on cn and then hands the session to the handler,
// unless the server was closed in the meantime. p is the record that
// ListenAndServe made for cn, or nil.
func (s *Server) serveConn(cn Conn, p *pendingConn) (err error) {
	defer func() {
		s.endHandshake(p)
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

	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	t, err := runResponder(ctx, cn, responderInput{
		attest:        s.attest,
		store:         s.storage,
		verify:        s.handshakeOpts.remoteVerifier,
		resumeEnabled: s.resumeEnabled,
		noPersistence: s.handshakeOpts.noPersistence,
		verifyTimeout: s.handshakeOpts.verifyTimeout,
		introTimeout:  s.introLimit(),
		name:          s.serverName,
		version:       s.version,
		clock:         s.clock,
		onHello:       func() error { return s.helloReceived(p) },
		onAuth:        func() error { return s.authenticated(p) },
		dropped:       func() bool { return s.connDropped(p) },
	})
	open := s.endHandshake(p)
	if err != nil {
		return err
	}
	if !open {
		_ = t.Close()
		return ErrClosedServer
	}
	herr := s.handlerFunc(t)
	t.dropIfUnreleased()
	if herr != nil {
		return fmt.Errorf("handler: %w", herr)
	}
	return nil
}

// startSweep deletes expired resumption rows now and every sweepInterval until
// Close. A server without persistence does not sweep.
func (s *Server) startSweep() {
	if s.handshakeOpts.noPersistence || s.storage == nil {
		return
	}
	s.mu.Lock()
	if s.sweepStarted || s.closed {
		s.mu.Unlock()
		return
	}
	s.sweepStarted = true
	s.mu.Unlock()

	s.sweepOnce()
	ticker := time.NewTicker(sweepInterval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-s.done:
				return
			case <-ticker.C:
				s.sweepOnce()
			}
		}
	}()
}

// sweepOnce runs one SweepSessions pass. The timestamp is the server clock; the
// interval between passes is wall time.
func (s *Server) sweepOnce() {
	if s.storage == nil {
		return
	}
	now := time.Now()
	if s.clock != nil {
		now = s.clock.Now()
	}
	n, err := s.storage.SweepSessions(
		now, defaultResumeIdle, defaultResumeMaxAge,
	)
	if err != nil {
		// A sweep that skipped some sessions still deleted n others.
		slog.Error("sweep sessions", slog.Any("error", err))
	}
	if n > 0 {
		slog.Info("swept idle sessions", slog.Int("deleted", n))
	}
}

// introLimit is how long an accepted connection has to send ClientHello.
// It is the shorter of the intro timeout and the handshake timeout.
func (s *Server) introLimit() time.Duration {
	limit := s.handshakeOpts.timeout
	if s.introTimeout > 0 && s.introTimeout < limit {
		limit = s.introTimeout
	}
	return limit
}

func (s *Server) PublicKey() []byte {
	return s.attest.MarshalPublicKey()
}

// NewServer creates a new server with the given address, handler, and storage.
// By default the server uses TCP on the given address when
// [Server.ListenAndServe] is called, unless a different listener or transport
// is configured via options. It returns [ErrMissingStorage] when store is nil,
// [ErrMissingVerifier] when rv is nil, and an error when [AppVersion] is not a
// valid version.
func NewServer(
	addr string,
	handler HandlerFunc,
	store *storage.Storage,
	rv RemoteVerifier,
	opts ...ServerOptions,
) (*Server, error) {
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
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		version:     version,
		addr:        addr,
		storage:     store,
		ctx:         ctx,
		cancel:      cancel,
		handlerFunc: handler,
		handshakeOpts: handshakeOpts{
			remoteVerifier: rv,
			timeout:        defaultHandshakeTimeout,
			verifyTimeout:  defaultVerifyTimeout,
		},
		clock:         clock.Real(),
		done:          make(chan struct{}),
		waiting:       stage{place: admitWaiting},
		hello:         stage{place: admitHello},
		introTimeout:  defaultIntroTimeout,
		maxPending:    defaultMaxPendingHandshakes,
		maxPerSource:  defaultMaxPendingPerSource,
		resumeEnabled: true,
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

	// Bind last, so that no other failure can leave the socket open.
	if s.listen != nil {
		l, err := s.listen()
		if err != nil {
			return nil, err
		}
		s.listener = l
		s.listen = nil
	}
	return s, nil
}

// ServerOptions configures the server. Returning an error from an option causes
// [NewServer] to fail immediately with that error.
type ServerOptions func(*Server) error

// ServeWithServerName sets the server's advertised name. The name must pass
// [ValidatePeerName], or [NewServer] fails, since peers reject a handshake
// whose name fails it. An empty name stands for the default, the
// [fingerprint.Sum] of the server's public key.
func ServeWithServerName(name string) ServerOptions {
	return func(s *Server) error {
		if err := ValidatePeerName(name); err != nil {
			return fmt.Errorf("server name: %w", err)
		}
		s.serverName = name
		return nil
	}
}

// ServeWithTCP configures the server to use TCP connections with the given
// connection options. If not called, TCP with default options is used.
// [NewServer] binds the address once everything else has succeeded, and returns
// the error if binding fails.
func ServeWithTCP(opts ...ConnOption) ServerOptions {
	return func(s *Server) error {
		s.connOpts = opts
		s.listener = nil
		s.listen = func() (Listener, error) {
			l, err := net.Listen("tcp", s.addr)
			if err != nil {
				return nil, fmt.Errorf("listening tcp: %w", err)
			}
			return &tcpListener{Listener: l, connOpts: opts}, nil
		}
		return nil
	}
}

// ServeWithUDP configures the server to use UDP connections, through the path
// layer of RFC008, with the given [UDPOption]s. The path layer answers only
// dialers that receive packets at their source address, so a sender that forges
// a source address gets no session, and the kamune handshake starts only on a
// path whose dialer has proved that it is return-routable. Such a path counts
// against [ServeWithMaxPendingPerSource] from accept, as a TCP connection does.
// [NewServer] binds the address once everything else has succeeded, and returns
// the error if binding fails.
func ServeWithUDP(opts ...UDPOption) ServerOptions {
	return func(s *Server) error {
		cfg, err := newUDPConfig(opts)
		if err != nil {
			return err
		}
		s.listener = nil
		s.listen = func() (Listener, error) {
			ua, err := net.ResolveUDPAddr("udp", s.addr)
			if err != nil {
				return nil, fmt.Errorf("resolving udp address: %w", err)
			}
			pc, err := net.ListenUDP("udp", ua)
			if err != nil {
				return nil, fmt.Errorf("listening udp: %w", err)
			}
			l, err := listenUDP(pc, cfg)
			if err != nil {
				_ = pc.Close()
				return nil, fmt.Errorf("listening udp: %w", err)
			}
			return l, nil
		}
		return nil
	}
}

// ServeWithListener uses the caller-provided Listener directly. The addr
// argument passed to [NewServer] is unused in this case; pass "".
func ServeWithListener(l Listener) ServerOptions {
	return func(s *Server) error {
		s.listener = l
		s.listen = nil
		return nil
	}
}

// ServeWithResumeEnabled controls whether the server may continue a stored
// session. When disabled, every resume offer is answered with a cold handshake.
// The [RemoteVerifier] still runs. Enabled by default.
//
// A stored session can be resumed while its row is inside the idle window (24
// hours since it was last touched) and the maximum age (7 days since the cold
// handshake). To stop one peer from resuming, delete it from storage with
// [storage.Storage.DeletePeer], or delete its sessions with
// [storage.Storage.DeleteSession].
func ServeWithResumeEnabled(enabled bool) ServerOptions {
	return func(s *Server) error {
		s.resumeEnabled = enabled
		return nil
	}
}

// ServeWithVerifyTimeout sets how long the [RemoteVerifier] may take to decide
// on a peer. The handshake deadline does not run while the verifier does, so a
// user has this long to compare fingerprints; a verifier that accepts later is
// treated as a rejection. The server also allows this long for the dialer's
// verifier when it waits for the dialer to go on. The default is 150 seconds; d
// must be positive.
func ServeWithVerifyTimeout(d time.Duration) ServerOptions {
	return func(s *Server) error {
		if d <= 0 {
			return fmt.Errorf("verify timeout is not positive: %v", d)
		}
		s.handshakeOpts.verifyTimeout = d
		return nil
	}
}

// ServeWithoutPersistence keeps the server from writing session state to
// storage, for incognito use. A session it accepts stores no resumption row,
// and closing it writes nothing either. An offer is answered with a cold
// handshake.
//
// The storage is still read for the server's identity and handed to the
// [RemoteVerifier], which decides on its own whether to store the peer.
func ServeWithoutPersistence() ServerOptions {
	return func(s *Server) error {
		s.handshakeOpts.noPersistence = true
		return nil
	}
}

// ServeWithMaxPendingHandshakes caps how many accepted connections may wait for
// ClientHello at the same time, and, separately, how many may sit in the hello
// stage before the dialer authenticates. [Server.ListenAndServe] keeps
// accepting at the cap: a new connection takes the place of one in the same
// stage, which is closed. To pick it, the server groups those connections by
// network, an IPv4 /24 or an IPv6 /48, takes the networks with the most of
// them, the new connection counted, and closes the oldest connection of one of
// those networks, picked at random. So idle connections from one network lose
// their places first, and idle connections from fewer networks than the cap
// never push out a dialer from another network that sends ClientHello within a
// few round trips.
//
// Idle connections from more networks than the cap can: each new one then
// closes a connection in that stage at random, so a dialer is more likely to
// lose its place the more of them arrive before it sends ClientHello. That
// takes many addresses on TCP, but a raw UDP or KCP connection of a custom
// [Listener] has a source that a sender can forge as many times as it likes,
// without receiving a reply. The cap still applies there, since each KCP
// session costs a few hundred kilobytes and without it such a sender could hold
// any number of them.
//
// A connection whose dialer has authenticated, for example one waiting for the
// [RemoteVerifier], no longer counts and is never closed this way, and neither
// are sessions handed to the handler. A full hello stage evicts a hello
// connection and never a waiting one. [ServeWithIntroTimeout] bounds how long
// an idle connection holds its place before ClientHello. The default is 256;
// n == 0 removes the cap, and a negative n is an error.
func ServeWithMaxPendingHandshakes(n int) ServerOptions {
	return func(s *Server) error {
		if n < 0 {
			return fmt.Errorf("max pending handshakes is negative: %d", n)
		}
		s.maxPending = n
		return nil
	}
}

// ServeWithMaxPendingPerSource caps how many connections from one source may be
// in the handshake at the same time, from the moment they are accepted until
// the handshake ends, verification included. A connection over the cap is
// closed as soon as it is accepted, so it does not take the place of a waiting
// connection (see [ServeWithMaxPendingHandshakes]). The source is the IP
// address of the connection's RemoteAddr, and for IPv6 its /64 prefix, since
// one host commonly holds a whole /64. A connection that does not report a
// remote address, such as a relay connection, is not limited.
//
// A connection whose source address can be forged, such as a raw UDP or KCP
// connection of a custom [Listener], counts only once its dialer has
// authenticated. Until then the dialer cannot have had the server's reply, and
// a sender could otherwise forge another host's address and use up that host's
// places. Such a connection over the cap is closed at that point. TCP
// connections and the UDP paths of [ServeWithUDP] count from accept. The
// default is 16; n == 0 removes the cap, and a negative n is an error.
func ServeWithMaxPendingPerSource(n int) ServerOptions {
	return func(s *Server) error {
		if n < 0 {
			return fmt.Errorf("max pending per source is negative: %d", n)
		}
		s.maxPerSource = n
		return nil
	}
}

// ServeWithIntroTimeout sets how long an accepted connection has to send
// ClientHello. A connection that has not done so in time is closed, which frees
// its place among the connections that [ServeWithMaxPendingHandshakes] caps.
// Once ClientHello has arrived, the rest of the handshake has the usual
// handshake timeout. The default is 10 seconds; d must be positive.
func ServeWithIntroTimeout(d time.Duration) ServerOptions {
	return func(s *Server) error {
		if d <= 0 {
			return fmt.Errorf("intro timeout is not positive: %v", d)
		}
		s.introTimeout = d
		return nil
	}
}

// ServeWithClock sets a custom clock for the server. It is primarily useful for
// tests that need to control time-dependent behavior like session expiry.
func ServeWithClock(c clock.Clock) ServerOptions {
	return func(s *Server) error {
		s.clock = c
		return nil
	}
}
