package ratelimit

import (
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
)

type RateLimiter struct {
	mu     sync.Mutex
	lru    *expirable.LRU[string, []time.Time]
	quota  int
	window time.Duration
}

func New(quota int, window time.Duration, maxEntries int) *RateLimiter {
	return &RateLimiter{
		lru:    expirable.NewLRU[string, []time.Time](maxEntries, nil, window*2),
		quota:  quota,
		window: window,
	}
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
