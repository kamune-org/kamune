package ratelimit

import (
	"math"
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/v2/simplelru"
)

// RateLimiter allows each key at most quota requests in any span of
// window. It keeps the request times of up to maxEntries keys, dropping
// the least recently used key to make room for a new one, and a goroutine
// started by New drops keys whose requests have all left the window. Close
// stops that goroutine.
type RateLimiter struct {
	lru *simplelru.LRU[string, []time.Time]
	// done is closed by Close to stop the sweep goroutine, which closes
	// stopped when it returns.
	done      chan struct{}
	stopped   chan struct{}
	quota     int
	window    time.Duration
	mu        sync.Mutex
	closeOnce sync.Once
}

// New returns a limiter of quota requests per window for each key that
// keeps up to maxEntries keys, or any number of keys when maxEntries is 0.
// The caller must call Close when it no longer needs the limiter.
func New(quota int, window time.Duration, maxEntries int) *RateLimiter {
	size := maxEntries
	if size <= 0 {
		size = math.MaxInt
	}
	// NewLRU fails only for a size below 1.
	lru, _ := simplelru.NewLRU[string, []time.Time](size, nil)
	rl := &RateLimiter{
		lru:     lru,
		done:    make(chan struct{}),
		stopped: make(chan struct{}),
		quota:   quota,
		window:  window,
	}
	if window > 0 {
		go rl.sweepLoop()
	} else {
		close(rl.stopped)
	}
	return rl
}

func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	// A new key starts with no history and grows it one stamp at a time.
	// Sizing it to quota up front cost 24*quota bytes per address that
	// sent a single request, which a high quota turns into gigabytes.
	stamps, _ := rl.lru.Get(key)

	i := 0
	for i < len(stamps) && !stamps[i].After(cutoff) {
		i++
	}
	stamps = stamps[i:]

	if len(stamps) >= rl.quota {
		return false
	}

	stamps = append(stamps, now)
	rl.lru.Add(key, stamps)
	return true
}

// Close stops the goroutine that drops expired keys and waits for it to
// return. Allow still works after Close, but it then drops a key only to
// make room for another. Close may be called more than once.
func (rl *RateLimiter) Close() {
	rl.closeOnce.Do(func() { close(rl.done) })
	<-rl.stopped
}

// sweepLoop calls sweep once per window until Close.
func (rl *RateLimiter) sweepLoop() {
	defer close(rl.stopped)
	ticker := time.NewTicker(rl.window)
	defer ticker.Stop()
	for {
		select {
		case <-rl.done:
			return
		case <-ticker.C:
			rl.sweep(time.Now())
		}
	}
}

// sweep drops keys whose requests all came a window or more before now,
// from the least recently used key on. It stops at the first key with a
// request inside the window: that key was used after the window began,
// so every key used since was too, and a later sweep handles them.
func (rl *RateLimiter) sweep(now time.Time) {
	cutoff := now.Add(-rl.window)
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for {
		key, stamps, ok := rl.lru.GetOldest()
		if !ok {
			return
		}
		if n := len(stamps); n > 0 && stamps[n-1].After(cutoff) {
			return
		}
		rl.lru.Remove(key)
	}
}
