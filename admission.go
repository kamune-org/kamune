package kamune

import (
	"errors"
	"log/slog"
	"math/rand/v2"
	"slices"
)

var (
	errDroppedForNewer = errors.New(
		"dropped for a newer connection before authentication",
	)
	errTooManyFromSource = errors.New(
		"too many pending handshakes from source",
	)
)

// admitPlace is which pre-authentication list a connection is on.
type admitPlace uint8

const (
	admitNone admitPlace = iota
	admitWaiting
	admitHello
)

// stage is one capped list of connections that have not authenticated.
// conns is in accept order. networks counts conns by network.
type stage struct {
	networks map[string]int
	conns    []*pendingConn
	place    admitPlace
}

func (g *stage) len() int { return len(g.conns) }

func (g *stage) add(p *pendingConn) {
	p.where = g.place
	g.conns = append(g.conns, p)
	if g.networks == nil {
		g.networks = make(map[string]int)
	}
	g.networks[p.network]++
}

func (g *stage) remove(p *pendingConn) {
	if p == nil || p.where != g.place {
		return
	}
	p.where = admitNone
	if g.networks[p.network] <= 1 {
		delete(g.networks, p.network)
	} else {
		g.networks[p.network]--
	}
	if i := slices.Index(g.conns, p); i >= 0 {
		g.conns = slices.Delete(g.conns, i, i+1)
	}
}

// dropCandidate returns the connection to drop for a new one from network.
// It takes the networks with the most connections, the new one counted,
// picks one of them at random and returns its oldest connection. g must
// not be empty.
func (g *stage) dropCandidate(network string) *pendingConn {
	in := func(n string) int {
		if n == network {
			return g.networks[n] + 1
		}
		return g.networks[n]
	}
	most := 0
	for n := range g.networks {
		most = max(most, in(n))
	}
	var victim *pendingConn
	seen := make(map[string]struct{}, len(g.networks))
	tied := 0
	for _, p := range g.conns {
		if _, ok := seen[p.network]; ok {
			continue
		}
		seen[p.network] = struct{}{}
		if in(p.network) < most {
			continue
		}
		tied++
		if rand.IntN(tied) == 0 {
			victim = p
		}
	}
	return victim
}

// helloReceived moves p from waiting to hello. Hello is capped on its own,
// so a full hello list evicts a hello connection and never a waiting one.
// p may be nil when ListenAndServe did not accept the connection.
func (s *Server) helloReceived(p *pendingConn) error {
	if p == nil {
		return nil
	}
	var dropped Conn
	s.mu.Lock()
	if p.dropped {
		s.mu.Unlock()
		return errDroppedForNewer
	}
	if p.where == admitHello || p.authenticated {
		s.mu.Unlock()
		return nil
	}
	s.waiting.remove(p)
	if s.maxPending > 0 {
		if s.hello.len() >= s.maxPending {
			victim := s.hello.dropCandidate(p.network)
			s.hello.remove(victim)
			victim.dropped = true
			dropped = victim.conn
			slog.Debug(
				"dropped hello connection for a newer one",
				slog.String("network", victim.network),
			)
		}
		s.hello.add(p)
	}
	s.mu.Unlock()
	if dropped != nil {
		_ = dropped.Close()
	}
	return nil
}

// authenticated removes p from hello, counts a forgeable source, and marks
// p authenticated. A non-forgeable source was counted in admit.
func (s *Server) authenticated(p *pendingConn) error {
	if p == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.dropped {
		return errDroppedForNewer
	}
	s.hello.remove(p)
	if p.source != "" && !p.counted && !s.countSourceLocked(p) {
		return errTooManyFromSource
	}
	p.authenticated = true
	return nil
}

// connDropped reports whether admission closed p to make room.
func (s *Server) connDropped(p *pendingConn) bool {
	if p == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return p.dropped
}

// wasAuthenticated reports whether the dialer on p proved its key.
func (s *Server) wasAuthenticated(p *pendingConn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return p.authenticated
}
