package ratelimit

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAllowWithinQuota(t *testing.T) {
	a := require.New(t)
	rl := New(5, time.Minute, 100)
	for i := range 5 {
		a.True(rl.Allow("1.2.3.4"), "attempt %d denied, expected allow", i+1)
	}
}

func TestBlockAfterQuota(t *testing.T) {
	a := require.New(t)
	rl := New(3, time.Minute, 100)
	for range 3 {
		rl.Allow("1.2.3.4")
	}
	a.False(rl.Allow("1.2.3.4"), "expected deny after quota exceeded")
}

func TestResetAfterWindow(t *testing.T) {
	a := require.New(t)
	rl := New(2, 50*time.Millisecond, 100)
	rl.Allow("1.2.3.4")
	rl.Allow("1.2.3.4")
	a.False(rl.Allow("1.2.3.4"), "expected deny after quota")
	time.Sleep(60 * time.Millisecond)
	a.True(rl.Allow("1.2.3.4"), "expected allow after window elapsed")
}

func TestMultipleIPsIndependent(t *testing.T) {
	a := require.New(t)
	rl := New(2, time.Minute, 100)
	rl.Allow("1.1.1.1")
	rl.Allow("1.1.1.1")
	rl.Allow("2.2.2.2")
	a.False(rl.Allow("1.1.1.1"), "expected deny for 1.1.1.1 after quota")
	a.True(rl.Allow("2.2.2.2"), "expected allow for 2.2.2.2 (separate quota)")
}

func TestConcurrentSameIP(t *testing.T) {
	a := require.New(t)
	rl := New(10, time.Minute, 100)
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			rl.Allow("1.2.3.4")
		})
	}
	wg.Wait()

	allowed := 0
	for range 20 {
		if rl.Allow("1.2.3.4") {
			allowed++
		}
	}
	a.Equal(0, allowed, "expected 0 allowed after quota, got %d", allowed)
}

func TestConcurrentDifferentIPs(t *testing.T) {
	a := require.New(t)
	rl := New(5, time.Minute, 100)
	var wg sync.WaitGroup
	for _, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		for range 5 {
			wg.Go(func() {
				rl.Allow(ip)
			})
		}
	}
	wg.Wait()

	for _, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		a.False(rl.Allow(ip), "expected deny for %s after concurrent quota fill", ip)
	}
}

func TestLRUSizeLimit(t *testing.T) {
	a := require.New(t)
	const quota = 3
	rl := New(quota, time.Minute, 2)

	// Fill both slots.
	a.True(rl.Allow("1.1.1.1"), "first allow for 1.1.1.1 should pass")
	a.True(rl.Allow("2.2.2.2"), "first allow for 2.2.2.2 should pass")

	// Adding a third key must evict the oldest entry (1.1.1.1).
	a.True(rl.Allow("3.3.3.3"), "first allow for 3.3.3.3 should pass")

	// 1.1.1.1 was evicted; its quota is now reset, so it must accept
	// up to `quota` requests before denying.
	for i := range quota {
		a.True(rl.Allow("1.1.1.1"), "allow #%d for evicted 1.1.1.1 should pass (LRU eviction reset the window)", i+1)
	}
	// ...and the (quota+1)th must be denied.
	a.False(rl.Allow("1.1.1.1"), "1.1.1.1 should be denied after refilling its quota")
}

func TestQuotaOne(t *testing.T) {
	a := require.New(t)
	rl := New(1, time.Minute, 100)
	a.True(rl.Allow("1.2.3.4"), "expected allow for first attempt with quota=1")
	a.False(rl.Allow("1.2.3.4"), "expected deny for second attempt with quota=1")
}

func TestHighQuota(t *testing.T) {
	a := require.New(t)
	n := 100
	rl := New(n, time.Minute, 1000)
	for i := range n {
		a.True(rl.Allow("1.2.3.4"), "attempt %d denied with quota=%d", i+1, n)
	}
}
