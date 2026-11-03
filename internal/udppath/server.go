package udppath

import (
	"crypto/rand"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kamune-org/kamune/internal/admit"
	"github.com/kamune-org/kamune/internal/clock"
)

// pathState is where a server path is in its life. Only the server moves a
// path between states.
type pathState uint8

const (
	// stateHalfOpen is a path that answered an INIT and has no DATA yet.
	stateHalfOpen pathState = iota + 1
	// stateQueued is a path whose first DATA opened. It waits for Accept.
	stateQueued
	// stateAccepted is a path that Accept has returned.
	stateAccepted
)

// secretLen is the size of the cookie secret, one per server.
const secretLen = 32

// serverEntry is the server-only state of a path. Server.mu guards queuedAt,
// state and removed. The other fields are set before the path is published
// and do not change after that.
type serverEntry struct {
	srv       *Server
	createdAt time.Time
	queuedAt  time.Time
	source    string
	network   string
	acceptPkt []byte
	cEph      [ephLen]byte
	state     pathState
	removed   bool
}

// expired reports whether the path is past its timeout at now. An accepted
// path has none.
func (e *serverEntry) expired(now time.Time) bool {
	switch e.state {
	case stateHalfOpen:
		return now.Sub(e.createdAt) > HalfOpenTimeout
	case stateQueued:
		return now.Sub(e.queuedAt) > QueuedTimeout
	default:
		return false
	}
}

// initKey identifies an INIT by its source and client id. A retransmit of an
// INIT has the same key.
type initKey struct {
	src netip.AddrPort
	cid uint32
}

// hsPacket is a HELLO or INIT that waits for the handshake worker. Both are
// HelloSize bytes, so one pooled buffer holds either.
type hsPacket struct {
	buf *[HelloSize]byte
	src netip.AddrPort
}

// hsPool holds the buffers of hsPacket.
var hsPool = sync.Pool{New: func() any { return new([HelloSize]byte) }}

// Server is the listening end of the path layer. It accepts the paths that
// clients dial to its socket, and it owns the socket from [NewServer] on.
type Server struct {
	pc    net.PacketConn
	clk   clock.Clock
	allow func(netip.AddrPort) bool
	// initRate limits the INITs of one source. It has its own lock.
	initRate *admit.Limiter
	rd       *reader
	knock    []byte
	secret   []byte
	hsQueue  chan hsPacket
	// acceptNotify wakes one Accept call. It holds at most one signal.
	acceptNotify chan struct{}
	// done is closed with closing, and closing is set under mu.
	done       chan struct{}
	workerDone chan struct{}
	tickDone   chan struct{}
	// byID maps the sid of each path, which is the rid of its DATA.
	byID map[uint32]*Path
	// byInit maps each INIT to the path it made, for retransmits.
	byInit map[initKey]*Path
	// sources, networks and pendingFrom count the paths of each source key
	// and network key, and the pending ones of each source key.
	sources     map[string]int
	networks    map[string]int
	pendingFrom map[string]int
	// paths lists every path in creation order.
	paths []*Path
	// acceptList holds the QUEUED paths, oldest first.
	acceptList []*Path
	lim        resolvedLimits
	stats      counters
	// pending counts the HALF_OPEN and QUEUED paths.
	pending  int
	accepted int
	// mu guards the tables and counts above, and the state of every path.
	mu sync.Mutex
	// sockClosed is set once, by the first closeSocket.
	sockClosed atomic.Bool
	closing    bool
}

// NewServer starts a server on pc, which the server owns from then on. It
// clears pc's read deadline and starts the socket reader, one handshake
// worker and the one-second sweep. On error pc stays the caller's.
func NewServer(pc net.PacketConn, cfg Config) (*Server, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	lim, err := cfg.Limits.resolve()
	if err != nil {
		return nil, err
	}
	clk := cfg.Clock
	if clk == nil {
		clk = clock.Real()
	}
	if err := pc.SetReadDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("udp path listener: %w", err)
	}
	s := &Server{
		pc:           pc,
		clk:          clk,
		allow:        cfg.Allow,
		initRate:     admit.NewLimiter(lim.initRate, initSlots, clk),
		knock:        cfg.KnockKey,
		secret:       make([]byte, secretLen),
		hsQueue:      make(chan hsPacket, HandshakeQueue),
		acceptNotify: make(chan struct{}, 1),
		done:         make(chan struct{}),
		workerDone:   make(chan struct{}),
		tickDone:     make(chan struct{}),
		byID:         make(map[uint32]*Path),
		byInit:       make(map[initKey]*Path),
		sources:      make(map[string]int),
		networks:     make(map[string]int),
		pendingFrom:  make(map[string]int),
		lim:          lim,
	}
	_, _ = rand.Read(s.secret)
	s.rd = newReader(pc, s, &s.stats)
	go s.rd.run()
	go s.work()
	go s.tick()
	return s, nil
}

// Accept waits for the next path whose client has sent its first DATA, and
// returns it in the accepted state. It returns [ErrListenerClosed] once the
// server is closed. Several goroutines may call Accept at once.
func (s *Server) Accept() (*Path, error) {
	for {
		s.sweep(s.clk.Now())
		s.mu.Lock()
		p := s.popLocked()
		if p != nil {
			if len(s.acceptList) > 0 {
				s.signalAccept()
			}
			s.mu.Unlock()
			return p, nil
		}
		closing := s.closing
		s.mu.Unlock()
		if closing {
			return nil, ErrListenerClosed
		}
		select {
		case <-s.acceptNotify:
		case <-s.done:
			return nil, ErrListenerClosed
		}
	}
}

// Close stops the server. Accept returns [ErrListenerClosed], every path that
// Accept has not returned is closed with CLOSE to its client, and HELLO and
// INIT are no longer answered. The socket closes now, or with the last path
// that Accept returned. Close is safe to call more than once.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return nil
	}
	s.closing = true
	close(s.done)
	var open []*Path
	for _, p := range slices.Clone(s.paths) {
		if p.entry.state != stateAccepted {
			s.removeLocked(p)
			open = append(open, p)
		}
	}
	noneLeft := s.accepted == 0
	s.mu.Unlock()
	for _, p := range open {
		p.close(reasonShutdown)
	}
	<-s.workerDone
	<-s.tickDone
	if noneLeft {
		s.closeSocket()
	}
	return nil
}

// Addr returns the local address of the server's socket.
func (s *Server) Addr() net.Addr { return s.pc.LocalAddr() }

// Stats returns a snapshot of the server's counters.
func (s *Server) Stats() Stats { return s.stats.snapshot() }

// handle runs on the reader goroutine with a datagram that passed
// validPacket. It sends a HELLO or INIT to the handshake worker, and routes a
// DATA or CLOSE to its path.
func (s *Server) handle(src netip.AddrPort, pkt []byte) {
	switch pkt[0] {
	case typeHello, typeInit:
		s.enqueue(src, pkt)
	case typeData, typeClose:
		s.route(src, pkt)
	default:
		s.stats.Unexpected.Add(1)
	}
}

// enqueue copies a HELLO or INIT into a pooled buffer and queues it for the
// worker. A full queue drops it, and the dialer retransmits.
func (s *Server) enqueue(src netip.AddrPort, pkt []byte) {
	if s.isClosing() {
		return
	}
	buf := hsPool.Get().(*[HelloSize]byte)
	copy(buf[:], pkt)
	select {
	case s.hsQueue <- hsPacket{buf: buf, src: src}:
	default:
		hsPool.Put(buf)
		s.stats.HandshakeDropped.Add(1)
	}
}

// route handles a DATA or CLOSE. The path is looked up by rid, and it must
// have been made for the address the packet came from.
func (s *Server) route(src netip.AddrPort, pkt []byte) {
	m, err := parseSealed(pkt)
	if err != nil {
		s.stats.Malformed.Add(1)
		return
	}
	s.mu.Lock()
	p := s.byID[m.rid]
	s.mu.Unlock()
	if p == nil || p.raddr != src {
		s.stats.NoPath.Add(1)
		return
	}
	if p.input(m, pkt) {
		s.markQueued(p)
	}
}

// markQueued moves a HALF_OPEN path to QUEUED once its first DATA opened, and
// wakes Accept.
func (s *Server) markQueued(p *Path) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := p.entry
	if e.removed || e.state != stateHalfOpen {
		return
	}
	e.state = stateQueued
	e.queuedAt = s.clk.Now()
	s.acceptList = append(s.acceptList, p)
	s.signalAccept()
}

// socketClosed runs on the reader goroutine when the socket is closed under
// it. Nothing can be sent any more, so every path ends and the server closes.
func (s *Server) socketClosed() {
	s.mu.Lock()
	all := slices.Clone(s.paths)
	for _, p := range all {
		s.removeLocked(p)
	}
	if !s.closing {
		s.closing = true
		close(s.done)
	}
	s.mu.Unlock()
	for _, p := range all {
		p.close(reasonSocket)
	}
}

// work is the handshake worker. It answers the queued HELLOs and INITs one
// at a time, and it is the only goroutine that inserts paths.
func (s *Server) work() {
	defer close(s.workerDone)
	for {
		select {
		case <-s.done:
			return
		case h := <-s.hsQueue:
			if !s.isClosing() {
				s.handshake(h.src, h.buf[:])
			}
			hsPool.Put(h.buf)
		}
	}
}

// handshake answers one HELLO or INIT from src. pkt is valid only during the
// call.
func (s *Server) handshake(src netip.AddrPort, pkt []byte) {
	if pkt[0] == typeHello {
		s.answerHello(src, pkt)
		return
	}
	s.answerInit(src, pkt)
}

// answerHello sends a COOKIE to the source of a HELLO. It keeps no state.
func (s *Server) answerHello(src netip.AddrPort, pkt []byte) {
	m, err := parseHello(pkt)
	if err != nil {
		s.stats.Malformed.Add(1)
		return
	}
	if !checkKnock(s.knock, m.mac1, pkt[:helloMAC1]) {
		s.stats.KnockFail.Add(1)
		return
	}
	if !s.allowed(src) {
		s.stats.Filtered.Add(1)
		return
	}
	s.stats.Hello.Add(1)
	c := makeCookie(s.secret, s.clk.Now(), m.cid, src)
	if s.send(src, encodeCookie(m.cid, c)) {
		s.stats.CookieSent.Add(1)
	}
}

// answerInit answers an INIT with a valid cookie. A retransmit gets the
// ACCEPT it already has, without a token or a second X25519. Any other INIT
// must pass the rate limit and the caps, and then it makes a new path.
func (s *Server) answerInit(src netip.AddrPort, pkt []byte) {
	m, err := parseInit(pkt)
	if err != nil {
		s.stats.Malformed.Add(1)
		return
	}
	if !checkKnock(s.knock, m.mac1, pkt[:initMAC1]) {
		s.stats.KnockFail.Add(1)
		return
	}
	if !s.allowed(src) {
		s.stats.Filtered.Add(1)
		return
	}
	now := s.clk.Now()
	if !validCookie(s.secret, m.cookie, m.cid, src, now) {
		s.stats.BadCookie.Add(1)
		return
	}
	s.sweep(now)
	sk := admit.SourceKeyAddrPort(src)
	nk := admit.NetworkKeyAddrPort(src)

	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return
	}
	if old := s.byInit[initKey{src: src, cid: m.cid}]; old != nil {
		var resend []byte
		if old.entry.cEph == m.cEph && !old.entry.removed {
			resend = old.entry.acceptPkt
		}
		s.mu.Unlock()
		if resend != nil {
			s.send(src, resend)
		}
		return
	}
	if !s.initRate.Allow(sk) {
		s.stats.RateLimited.Add(1)
		s.mu.Unlock()
		return
	}
	if s.overSourceCapLocked(sk, nk) {
		s.stats.PathsFull.Add(1)
		s.mu.Unlock()
		return
	}
	sid := s.freeSIDLocked()
	s.mu.Unlock()

	out, err := responderAccept(m, sid)
	if err != nil {
		s.stats.Malformed.Add(1)
		return
	}
	p := newPath(roleServer, s.pc, &s.stats, src, m.cid, sid, out.keys)
	p.entry = &serverEntry{
		srv:       s,
		source:    sk,
		network:   nk,
		acceptPkt: out.pkt,
		cEph:      m.cEph,
		state:     stateHalfOpen,
	}

	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return
	}
	victims, ok := s.victimsLocked(nk)
	if !ok {
		s.stats.PathsFull.Add(1)
		s.mu.Unlock()
		return
	}
	for _, v := range victims {
		s.removeLocked(v)
	}
	s.insertLocked(p, s.clk.Now())
	s.mu.Unlock()

	for _, v := range victims {
		s.stats.Evicted.Add(1)
		v.close(reasonEvicted)
	}
	s.send(src, out.pkt)
}

// overSourceCapLocked reports whether a per-source or per-network cap refuses
// an INIT from the source key sk and the network key nk. The caller holds mu.
func (s *Server) overSourceCapLocked(sk, nk string) bool {
	l := s.lim
	pending := l.maxPendingPerSource >= 0 &&
		s.pendingFrom[sk] >= l.maxPendingPerSource
	perSource := l.maxPathsPerSource >= 0 &&
		s.sources[sk] >= l.maxPathsPerSource
	perNetwork := l.maxPathsPerNetwork >= 0 &&
		s.networks[nk] >= l.maxPathsPerNetwork
	return pending || perSource || perNetwork
}

// victimsLocked returns the paths that a new INIT from the network nk evicts
// to fit under the pending and total caps. It removes nothing. ok is false
// when a cap refuses the INIT, because no path can go. The caller holds mu.
func (s *Server) victimsLocked(nk string) (victims []*Path, ok bool) {
	var pending *Path
	if s.pending >= s.lim.maxPending {
		pending = s.victimLocked(true, nk, nil)
		if pending == nil {
			return nil, false
		}
		victims = append(victims, pending)
	}
	n := len(s.paths)
	if pending != nil {
		n--
	}
	if n >= s.lim.maxPaths {
		v := s.victimLocked(false, nk, pending)
		if v == nil {
			return nil, false
		}
		victims = append(victims, v)
	}
	return victims, true
}

// freeSIDLocked returns a random server id that no path uses. Only the worker
// inserts paths, so the id stays free until the worker inserts its path. The
// caller holds mu.
func (s *Server) freeSIDLocked() uint32 {
	for {
		sid := randomID()
		if _, used := s.byID[sid]; !used {
			return sid
		}
	}
}

// insertLocked publishes the HALF_OPEN path p in every table and count. The
// caller holds mu and has made room for p.
func (s *Server) insertLocked(p *Path, now time.Time) {
	e := p.entry
	e.createdAt = now
	s.byID[p.sid] = p
	s.byInit[initKey{src: p.raddr, cid: p.cid}] = p
	s.sources[e.source]++
	s.networks[e.network]++
	s.pending++
	s.pendingFrom[e.source]++
	s.paths = append(s.paths, p)
}

// removeLocked takes p out of every table and count. It reports whether p was
// accepted. A path is removed once, so a second call does nothing. The caller
// holds mu.
func (s *Server) removeLocked(p *Path) bool {
	e := p.entry
	if e.removed {
		return false
	}
	e.removed = true
	if s.byID[p.sid] == p {
		delete(s.byID, p.sid)
	}
	key := initKey{src: p.raddr, cid: p.cid}
	if s.byInit[key] == p {
		delete(s.byInit, key)
	}
	s.paths = slices.DeleteFunc(s.paths, func(q *Path) bool { return q == p })
	decCount(s.sources, e.source)
	decCount(s.networks, e.network)
	switch e.state {
	case stateHalfOpen:
		s.dropPendingLocked(e)
	case stateQueued:
		s.acceptList = slices.DeleteFunc(
			s.acceptList, func(q *Path) bool { return q == p },
		)
		s.dropPendingLocked(e)
	case stateAccepted:
		s.accepted--
		return true
	}
	return false
}

// dropPendingLocked counts a path that stops being pending. The caller holds
// mu.
func (s *Server) dropPendingLocked(e *serverEntry) {
	s.pending--
	decCount(s.pendingFrom, e.source)
}

// popLocked takes the oldest QUEUED path and marks it accepted. It returns
// nil when there is none. The caller holds mu.
func (s *Server) popLocked() *Path {
	for len(s.acceptList) > 0 {
		p := s.acceptList[0]
		s.acceptList = slices.Delete(s.acceptList, 0, 1)
		e := p.entry
		if e.removed || e.state != stateQueued {
			continue
		}
		e.state = stateAccepted
		s.dropPendingLocked(e)
		s.accepted++
		return p
	}
	return nil
}

// sweep closes the HALF_OPEN and QUEUED paths that are past their timeouts at
// now. It runs on the ticker, before every INIT and at every Accept.
func (s *Server) sweep(now time.Time) {
	s.mu.Lock()
	var expired []*Path
	for _, p := range s.paths {
		if p.entry.expired(now) {
			expired = append(expired, p)
		}
	}
	for _, p := range expired {
		s.removeLocked(p)
	}
	s.mu.Unlock()
	for _, p := range expired {
		s.stats.Expired.Add(1)
		p.close(reasonExpired)
	}
}

// remove runs when a server path closes. Once the server is closing, the
// socket closes with the last path that Accept returned.
func (s *Server) remove(p *Path) {
	s.mu.Lock()
	wasAccepted := s.removeLocked(p)
	last := wasAccepted && s.closing && s.accepted == 0
	s.mu.Unlock()
	if last {
		s.closeSocket()
	}
}

// closeSocket stops the reader and closes the socket. Only the first call
// does anything.
func (s *Server) closeSocket() {
	if !s.sockClosed.CompareAndSwap(false, true) {
		return
	}
	s.rd.halt()
	_ = s.pc.Close()
}

// tick runs the one-second sweep until the server closes.
func (s *Server) tick() {
	defer close(s.tickDone)
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
			s.sweep(s.clk.Now())
		}
	}
}

// signalAccept wakes one Accept call. The signal waits in the channel when no
// call is waiting. The caller holds mu.
func (s *Server) signalAccept() {
	select {
	case s.acceptNotify <- struct{}{}:
	default:
	}
}

// isClosing reports whether the server is closing. It is true exactly when
// done is closed, and it takes no lock.
func (s *Server) isClosing() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

// allowed reports whether Config.Allow admits src. Nil admits every source.
func (s *Server) allowed(src netip.AddrPort) bool {
	return s.allow == nil || s.allow(src)
}

// send writes pkt to to from the server's socket. It reports whether the
// write went through.
func (s *Server) send(to netip.AddrPort, pkt []byte) bool {
	_, err := s.pc.WriteTo(pkt, net.UDPAddrFromAddrPort(to))
	return err == nil
}

// decCount lowers the count of key by one, and drops the entry at zero.
func decCount(counts map[string]int, key string) {
	counts[key]--
	if counts[key] <= 0 {
		delete(counts, key)
	}
}
