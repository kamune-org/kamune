package ratelimit

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// newLimiter returns New(quota, window, maxEntries), closed when t ends.
func newLimiter(
	t *testing.T, quota int, window time.Duration, maxEntries int,
) *RateLimiter {
	t.Helper()
	rl := New(quota, window, maxEntries)
	t.Cleanup(rl.Close)
	return rl
}

func TestAllowWithinQuota(t *testing.T) {
	a := require.New(t)
	rl := newLimiter(t, 5, time.Minute, 100)
	for i := range 5 {
		a.True(rl.Allow("1.2.3.4"), "attempt %d denied, expected allow", i+1)
	}
}

func TestBlockAfterQuota(t *testing.T) {
	a := require.New(t)
	rl := newLimiter(t, 3, time.Minute, 100)
	for range 3 {
		rl.Allow("1.2.3.4")
	}
	a.False(rl.Allow("1.2.3.4"), "expected deny after quota exceeded")
}

func TestResetAfterWindow(t *testing.T) {
	a := require.New(t)
	rl := newLimiter(t, 2, 50*time.Millisecond, 100)
	rl.Allow("1.2.3.4")
	rl.Allow("1.2.3.4")
	a.False(rl.Allow("1.2.3.4"), "expected deny after quota")
	time.Sleep(60 * time.Millisecond)
	a.True(rl.Allow("1.2.3.4"), "expected allow after window elapsed")
}

func TestMultipleIPsIndependent(t *testing.T) {
	a := require.New(t)
	rl := newLimiter(t, 2, time.Minute, 100)
	rl.Allow("1.1.1.1")
	rl.Allow("1.1.1.1")
	rl.Allow("2.2.2.2")
	a.False(rl.Allow("1.1.1.1"), "expected deny for 1.1.1.1 after quota")
	a.True(rl.Allow("2.2.2.2"), "expected allow for 2.2.2.2 (separate quota)")
}

func TestConcurrentSameIP(t *testing.T) {
	a := require.New(t)
	rl := newLimiter(t, 10, time.Minute, 100)
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
	rl := newLimiter(t, 5, time.Minute, 100)
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
	rl := newLimiter(t, quota, time.Minute, 2)

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
	rl := newLimiter(t, 1, time.Minute, 100)
	a.True(rl.Allow("1.2.3.4"), "expected allow for first attempt with quota=1")
	a.False(rl.Allow("1.2.3.4"), "expected deny for second attempt with quota=1")
}

func TestHighQuota(t *testing.T) {
	a := require.New(t)
	n := 100
	rl := newLimiter(t, n, time.Minute, 1000)
	for i := range n {
		a.True(rl.Allow("1.2.3.4"), "attempt %d denied with quota=%d", i+1, n)
	}
}

func TestNewKeyDoesNotReserveQuota(t *testing.T) {
	a := require.New(t)
	const quota = 1 << 20
	rl := newLimiter(t, quota, time.Minute, 100)
	a.True(rl.Allow("1.2.3.4"))
	stamps, ok := rl.lru.Get("1.2.3.4")
	a.True(ok)
	a.Len(stamps, 1)
	a.Less(
		cap(stamps), 64,
		"one request must not reserve room for the whole quota",
	)
}

// TestSweep checks which keys a sweep drops: those whose requests have all
// left the window, from the least recently used key up to the first one
// with a request inside the window.
func TestSweep(t *testing.T) {
	const window = time.Minute
	base := time.Now()
	type entry struct {
		key string
		// ago is how long before the sweep the key's last request came.
		ago time.Duration
	}
	tests := []struct {
		name    string
		entries []entry // least recently used first
		want    []string
	}{
		{name: "empty"},
		{
			name:    "all inside the window",
			entries: []entry{{"a", time.Second}, {"b", 0}},
			want:    []string{"a", "b"},
		},
		{
			name:    "all expired",
			entries: []entry{{"a", 2 * window}, {"b", window}},
		},
		{
			name: "expired keys before a live one",
			entries: []entry{
				{"a", 3 * window}, {"b", window + time.Second},
				{"c", time.Second}, {"d", 0},
			},
			want: []string{"c", "d"},
		},
		{
			// A key used after a live one waits for a later sweep.
			name:    "expired key after a live one",
			entries: []entry{{"a", time.Second}, {"b", 2 * window}},
			want:    []string{"a", "b"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			rl := newLimiter(t, 5, window, 100)
			now := base.Add(4 * window)
			for _, e := range tc.entries {
				rl.lru.Add(e.key, []time.Time{
					now.Add(-e.ago - time.Second), now.Add(-e.ago),
				})
			}
			rl.sweep(now)
			a.ElementsMatch(tc.want, rl.lru.Keys())
		})
	}
}

// TestSweepLoopDropsExpiredKeys checks that the goroutine New starts drops
// a key once its requests have left the window.
func TestSweepLoopDropsExpiredKeys(t *testing.T) {
	a := require.New(t)
	rl := newLimiter(t, 1, 10*time.Millisecond, 100)
	a.True(rl.Allow("1.2.3.4"))
	a.Eventually(func() bool {
		rl.mu.Lock()
		defer rl.mu.Unlock()
		return rl.lru.Len() == 0
	}, 10*time.Second, 10*time.Millisecond)
}

// TestClose checks that Close stops the sweep goroutine, may be called
// twice, and leaves Allow working.
func TestClose(t *testing.T) {
	tests := []struct {
		name   string
		window time.Duration
	}{
		{"with sweep", time.Minute},
		{"without window", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			rl := New(1, tc.window, 100)
			rl.Close()
			select {
			case <-rl.stopped:
			default:
				a.Fail("Close returned before the sweep goroutine")
			}
			rl.Close()
			a.True(rl.Allow("1.2.3.4"))
		})
	}
}

// TestUnboundedEntries checks that maxEntries 0 keeps every key.
func TestUnboundedEntries(t *testing.T) {
	a := require.New(t)
	rl := newLimiter(t, 1, time.Minute, 0)
	for i := range 1000 {
		a.True(rl.Allow(fmt.Sprintf("10.0.%d.%d", i/256, i%256)))
	}
	a.Equal(1000, rl.lru.Len())
	a.False(rl.Allow("10.0.0.0"))
}
