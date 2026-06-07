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

	stamps, ok := rl.lru.Get(key)
	if !ok {
		stamps = make([]time.Time, 0, rl.quota)
	}

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
