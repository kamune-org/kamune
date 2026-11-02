package udppath

import "sync/atomic"

// Stats is a snapshot of the path layer's counters, for tests and debugging.
type Stats struct {
	Hello            uint64 // HELLOs that passed the knock and filter checks
	CookieSent       uint64
	BadCookie        uint64
	KnockFail        uint64
	Filtered         uint64
	RateLimited      uint64
	PathsFull        uint64
	Evicted          uint64
	Expired          uint64
	HandshakeDropped uint64 // HELLO or INIT that found the queue full
	BadTag           uint64
	Replay           uint64
	NoPath           uint64 // DATA or CLOSE for no path of its source
	InboundDropped   uint64 // opened DATA that found the path queue full
	Malformed        uint64
	Unexpected       uint64 // a valid packet the receiver does not expect
	Kick             uint64
	Foreign          uint64
	ReadErrors       uint64
	CloseSent        uint64
	CloseReceived    uint64
}

// counters are the live values behind [Stats], one set per socket.
type counters struct {
	Hello            atomic.Uint64
	CookieSent       atomic.Uint64
	BadCookie        atomic.Uint64
	KnockFail        atomic.Uint64
	Filtered         atomic.Uint64
	RateLimited      atomic.Uint64
	PathsFull        atomic.Uint64
	Evicted          atomic.Uint64
	Expired          atomic.Uint64
	HandshakeDropped atomic.Uint64
	BadTag           atomic.Uint64
	Replay           atomic.Uint64
	NoPath           atomic.Uint64
	InboundDropped   atomic.Uint64
	Malformed        atomic.Uint64
	Unexpected       atomic.Uint64
	Kick             atomic.Uint64
	Foreign          atomic.Uint64
	ReadErrors       atomic.Uint64
	CloseSent        atomic.Uint64
	CloseReceived    atomic.Uint64
}

func (c *counters) snapshot() Stats {
	return Stats{
		Hello:            c.Hello.Load(),
		CookieSent:       c.CookieSent.Load(),
		BadCookie:        c.BadCookie.Load(),
		KnockFail:        c.KnockFail.Load(),
		Filtered:         c.Filtered.Load(),
		RateLimited:      c.RateLimited.Load(),
		PathsFull:        c.PathsFull.Load(),
		Evicted:          c.Evicted.Load(),
		Expired:          c.Expired.Load(),
		HandshakeDropped: c.HandshakeDropped.Load(),
		BadTag:           c.BadTag.Load(),
		Replay:           c.Replay.Load(),
		NoPath:           c.NoPath.Load(),
		InboundDropped:   c.InboundDropped.Load(),
		Malformed:        c.Malformed.Load(),
		Unexpected:       c.Unexpected.Load(),
		Kick:             c.Kick.Load(),
		Foreign:          c.Foreign.Load(),
		ReadErrors:       c.ReadErrors.Load(),
		CloseSent:        c.CloseSent.Load(),
		CloseReceived:    c.CloseReceived.Load(),
	}
}
