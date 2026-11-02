package admit

import (
	"fmt"
	"hash/maphash"
	"math"
	"sync"

	"github.com/kamune-org/kamune/internal/clock"
)

// Rate is one bucket's refill speed and maximum size.
// A PerSecond of zero disables the limiter.
type Rate struct {
	PerSecond float64
	Burst     int
}

// Validate reports an error for a rate that no bucket can apply: a
// negative, infinite or NaN PerSecond, or an enabled rate whose Burst
// is below one, which would refuse every key.
func (r Rate) Validate() error {
	switch {
	case math.IsNaN(r.PerSecond) || math.IsInf(r.PerSecond, 0):
		return fmt.Errorf("rate per second is not finite: %v", r.PerSecond)
	case r.PerSecond < 0:
		return fmt.Errorf("rate per second is negative: %v", r.PerSecond)
	case r.Burst < 0:
		return fmt.Errorf("rate burst is negative: %d", r.Burst)
	case r.PerSecond > 0 && r.Burst < 1:
		return fmt.Errorf("rate burst is below one: %d", r.Burst)
	}
	return nil
}

// slot is one token bucket. Keys that share a slot share its tokens.
type slot struct {
	tokens float32
	last   int64
}

// seed is chosen once per process so a peer cannot predict collisions.
var seed = maphash.MakeSeed()

// Limiter is a fixed set of token buckets. A key selects
// maphash.String(seed, key) modulo the slot count. The count is
// fixed at creation. A collision shares a bucket, which is stricter
// and never looser. Allow does not allocate. One mutex covers
// concurrent use.
type Limiter struct {
	clk   clock.Clock
	slots []slot
	rate  Rate
	seed  maphash.Seed
	mu    sync.Mutex
}

// NewLimiter returns a limiter with slots buckets. A nil clock uses
// clock.Real. It panics when r fails [Rate.Validate], when slots is
// negative, or when the rate is enabled and slots is zero: callers
// check user input first.
func NewLimiter(r Rate, slots int, clk clock.Clock) *Limiter {
	if err := r.Validate(); err != nil {
		panic("admit: " + err.Error())
	}
	if slots < 0 || (r.PerSecond > 0 && slots < 1) {
		panic(fmt.Sprintf("admit: limiter slots out of range: %d", slots))
	}
	if clk == nil {
		clk = clock.Real()
	}
	buckets := make([]slot, slots)
	now := clk.Now().UnixNano()
	burst := float32(r.Burst)
	for i := range buckets {
		buckets[i].tokens = burst
		buckets[i].last = now
	}
	return &Limiter{
		slots: buckets,
		clk:   clk,
		rate:  r,
		seed:  seed,
	}
}

// Allow reports whether key has a token. A zero per-second rate
// always allows and does not touch the buckets.
func (l *Limiter) Allow(key string) bool {
	if l.rate.PerSecond == 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clk.Now().UnixNano()
	i := maphash.String(l.seed, key) % uint64(len(l.slots))
	b := &l.slots[i]
	if now > b.last {
		secs := float64(now-b.last) / 1e9
		b.tokens += float32(secs * l.rate.PerSecond)
		burst := float32(l.rate.Burst)
		if b.tokens > burst {
			b.tokens = burst
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
