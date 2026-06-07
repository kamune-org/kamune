package ratelimit

import (
	"sync"
	"testing"
	"time"
)

func TestAllowWithinQuota(t *testing.T) {
	rl := New(5, time.Minute, 100)
	for i := range 5 {
		if !rl.Allow("1.2.3.4") {
			t.Fatalf("attempt %d denied, expected allow", i+1)
		}
	}
}

func TestBlockAfterQuota(t *testing.T) {
	rl := New(3, time.Minute, 100)
	for range 3 {
		rl.Allow("1.2.3.4")
	}
	if rl.Allow("1.2.3.4") {
		t.Fatal("expected deny after quota exceeded")
	}
}

func TestResetAfterWindow(t *testing.T) {
	rl := New(2, 50*time.Millisecond, 100)
	rl.Allow("1.2.3.4")
	rl.Allow("1.2.3.4")
	if rl.Allow("1.2.3.4") {
		t.Fatal("expected deny after quota")
	}
	time.Sleep(60 * time.Millisecond)
	if !rl.Allow("1.2.3.4") {
		t.Fatal("expected allow after window elapsed")
	}
}

func TestMultipleIPsIndependent(t *testing.T) {
	rl := New(2, time.Minute, 100)
	rl.Allow("1.1.1.1")
	rl.Allow("1.1.1.1")
	rl.Allow("2.2.2.2")
	if rl.Allow("1.1.1.1") {
		t.Fatal("expected deny for 1.1.1.1 after quota")
	}
	if !rl.Allow("2.2.2.2") {
		t.Fatal("expected allow for 2.2.2.2 (separate quota)")
	}
}

func TestConcurrentSameIP(t *testing.T) {
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
	if allowed > 0 {
		t.Fatalf("expected 0 allowed after quota, got %d", allowed)
	}
}

func TestConcurrentDifferentIPs(t *testing.T) {
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
		if rl.Allow(ip) {
			t.Fatalf("expected deny for %s after concurrent quota fill", ip)
		}
	}
}

func TestLRUSizeLimit(t *testing.T) {
	rl := New(1, time.Minute, 2)
	rl.Allow("1.1.1.1")
	rl.Allow("2.2.2.2")
	rl.Allow("3.3.3.3")
}

func TestQuotaOne(t *testing.T) {
	rl := New(1, time.Minute, 100)
	if !rl.Allow("1.2.3.4") {
		t.Fatal("expected allow for first attempt with quota=1")
	}
	if rl.Allow("1.2.3.4") {
		t.Fatal("expected deny for second attempt with quota=1")
	}
}

func TestHighQuota(t *testing.T) {
	n := 100
	rl := New(n, time.Minute, 1000)
	for i := range n {
		if !rl.Allow("1.2.3.4") {
			t.Fatalf("attempt %d denied with quota=%d", i+1, n)
		}
	}
}
