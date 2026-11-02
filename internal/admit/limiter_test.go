package admit_test

import (
	"math"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/internal/admit"
	"github.com/kamune-org/kamune/internal/clock"
)

// networkSlots is the default handshake network limiter size.
const networkSlots = 16384

func TestLimiter(t *testing.T) {
	start := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "burst then refill",
			run:  func(t *testing.T) { testLimiterBurst(t, start) },
		},
		{
			name: "zero per second",
			run:  testLimiterZero,
		},
		{
			name: "five thousand keys from one /48",
			run:  func(t *testing.T) { testLimiterManyKeys(t, start) },
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.run(t)
		})
	}
}

func testLimiterBurst(t *testing.T, start time.Time) {
	a := require.New(t)
	clk := clock.NewFake(start)
	lim := admit.NewLimiter(admit.Rate{PerSecond: 4, Burst: 8}, 8, clk)
	const key = "198.51.100.10"
	for range 8 {
		a.True(lim.Allow(key))
	}
	a.False(lim.Allow(key))
	clk.Advance(time.Second)
	// PerSecond tokens come back: the first of these is the refilled allow.
	for range 4 {
		a.True(lim.Allow(key))
	}
	a.False(lim.Allow(key))
}

func testLimiterZero(t *testing.T) {
	a := require.New(t)
	lim := admit.NewLimiter(admit.Rate{}, 1, nil)
	for range 30 {
		a.True(lim.Allow("198.51.100.10"))
		a.True(lim.Allow("198.51.100.11"))
	}
}

func testLimiterManyKeys(t *testing.T, start time.Time) {
	a := require.New(t)
	const n = 5000
	const burst = 8
	rate := admit.Rate{PerSecond: 4, Burst: burst}
	source, network := keysFrom48(n)
	seen := make(map[string]struct{}, n)
	for _, key := range source {
		seen[key] = struct{}{}
	}
	a.Len(seen, n)

	// One slot forces every source key onto one bucket.
	clk := clock.NewFake(start)
	one := admit.NewLimiter(rate, 1, clk)
	got := drainAllows(one, source)
	a.Equal(burst, got)
	clk.Advance(time.Second)
	got = drainAllows(one, source)
	a.Equal(int(rate.PerSecond), got)

	// Default network size. Distinct source keys can use more than one
	// bucket; the sum still cannot exceed one burst per key. The shared
	// network key of this /48 stays within one bucket on its own.
	clk = clock.NewFake(start)
	wide := admit.NewLimiter(rate, networkSlots, clk)
	got = drainAllows(wide, source)
	a.Greater(got, burst)
	a.LessOrEqual(got, n*burst)

	clk = clock.NewFake(start)
	netLim := admit.NewLimiter(rate, networkSlots, clk)
	same := make([]string, n)
	for i := range same {
		same[i] = network
	}
	got = drainAllows(netLim, same)
	a.Equal(burst, got)
}

func TestLimiterAllocs(t *testing.T) {
	a := require.New(t)
	clk := clock.NewFake(time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC))
	lim := admit.NewLimiter(admit.Rate{PerSecond: 4, Burst: 8}, 64, clk)
	keys := []string{"198.51.100.1", "198.51.100.2", "2001:db8:1::/48"}
	var n int
	allocs := testing.AllocsPerRun(100, func() {
		lim.Allow(keys[n%len(keys)])
		n++
	})
	a.Zero(allocs)
}

// keysFrom48 returns n distinct IPv6 /64 source keys inside
// 2001:db8:1::/48 and that network key.
func keysFrom48(n int) (source []string, network string) {
	source = make([]string, n)
	for i := range source {
		var addr [16]byte
		addr[0], addr[1], addr[2], addr[3] = 0x20, 0x01, 0x0d, 0xb8
		addr[4], addr[5] = 0x00, 0x01
		addr[6], addr[7] = byte(i>>8), byte(i)
		ap := netip.AddrPortFrom(netip.AddrFrom16(addr), 9)
		source[i] = admit.SourceKeyAddrPort(ap)
		network = admit.NetworkKeyAddrPort(ap)
	}
	return source, network
}

// drainAllows counts successful Allow calls over keys until every key
// is refused. The cap is one past eight tokens per key, which is more
// than the burst these tests use, so a limiter that never refuses stops.
func drainAllows(lim *admit.Limiter, keys []string) int {
	limit := len(keys)*8 + 1
	n := 0
	for n < limit {
		hit := false
		for _, key := range keys {
			if !lim.Allow(key) {
				continue
			}
			n++
			hit = true
			if n == limit {
				return n
			}
		}
		if !hit {
			return n
		}
	}
	return n
}

func TestRateValidate(t *testing.T) {
	tests := []struct {
		name  string
		rate  admit.Rate
		valid bool
	}{
		{name: "disabled", rate: admit.Rate{}, valid: true},
		{name: "enabled", rate: admit.Rate{PerSecond: 4, Burst: 8}, valid: true},
		{name: "negative rate", rate: admit.Rate{PerSecond: -1, Burst: 8}},
		{name: "infinite rate", rate: admit.Rate{PerSecond: math.Inf(1), Burst: 8}},
		{name: "nan rate", rate: admit.Rate{PerSecond: math.NaN(), Burst: 8}},
		{name: "negative burst", rate: admit.Rate{Burst: -1}},
		{name: "enabled zero burst", rate: admit.Rate{PerSecond: 4}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			err := tc.rate.Validate()
			if tc.valid {
				a.NoError(err)
				a.NotPanics(func() { admit.NewLimiter(tc.rate, 1, nil) })
				return
			}
			a.Error(err)
			a.Panics(func() { admit.NewLimiter(tc.rate, 1, nil) })
		})
	}
}

func TestNewLimiterSlots(t *testing.T) {
	a := require.New(t)
	enabled := admit.Rate{PerSecond: 4, Burst: 8}
	a.Panics(func() { admit.NewLimiter(enabled, 0, nil) })
	a.Panics(func() { admit.NewLimiter(admit.Rate{}, -1, nil) })
	lim := admit.NewLimiter(admit.Rate{}, 0, nil)
	a.True(lim.Allow("198.51.100.10"))
}
