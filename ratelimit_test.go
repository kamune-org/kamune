package kamune

import (
	"context"
	"fmt"
	"math"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/internal/clock"
	"github.com/kamune-org/kamune/pkg/storage"
)

// newRateServer returns a server for direct admit calls on a fake clock. The
// per-source cap is lifted, so that only the handshake rate limit refuses a
// connection. opts come last.
func newRateServer(
	t *testing.T, clk clock.Clock, opts ...ServerOptions,
) *Server {
	t.Helper()
	a := require.New(t)
	store, cleanup := newTestStore(t)
	t.Cleanup(cleanup)
	server, err := NewServer(
		"",
		func(*Transport) error { return nil },
		store,
		func(context.Context, *storage.Storage, VerifyRequest) error {
			return nil
		},
		append([]ServerOptions{
			ServeWithListener(newTestListener(net.ErrClosed)),
			ServeWithClock(clk),
			ServeWithMaxPendingPerSource(0),
		}, opts...)...,
	)
	a.NoError(err)
	return server
}

// admitted reports whether the server admits cn, and ends the handshake of an
// admitted one so that it holds no place.
func admitted(server *Server, cn Conn) bool {
	p, _, ok := server.admit(cn)
	if ok {
		server.endHandshake(p)
	}
	return ok
}

func TestHandshakeRatePerSource(t *testing.T) {
	a := require.New(t)
	clk := clock.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	server := newRateServer(t, clk)

	burst := defaultSourceRateBurst
	for i := range burst + 1 {
		addr := fmt.Sprintf("10.0.0.1:%d", i+1)
		a.Equal(
			i < burst, admitted(server, newSourceConn(nil, addr)),
			"admit %d", i,
		)
	}
	a.True(
		admitted(server, newSourceConn(nil, "10.0.0.2:1")),
		"another source was refused",
	)

	// The bucket refills 8 tokens a second, so one token takes 1/8 s.
	clk.Advance(time.Second / defaultSourceRatePerSecond)
	a.True(
		admitted(server, newSourceConn(nil, "10.0.0.1:100")),
		"the refilled token was not given",
	)
	a.False(
		admitted(server, newSourceConn(nil, "10.0.0.1:101")),
		"a second token was given",
	)
}

func TestHandshakeRatePerNetwork(t *testing.T) {
	a := require.New(t)
	clk := clock.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	server := newRateServer(t, clk)

	// Each source is within its own limit, but the network is not.
	burst := defaultNetworkRateBurst
	for i := range burst + 1 {
		addr := fmt.Sprintf("10.0.1.%d:1", i+1)
		a.Equal(
			i < burst, admitted(server, newSourceConn(nil, addr)),
			"source %d", i,
		)
	}
	a.True(
		admitted(server, newSourceConn(nil, "10.0.2.1:1")),
		"a source in another network was refused",
	)

	clk.Advance(time.Second / defaultNetworkRatePerSecond)
	a.True(admitted(server, newSourceConn(nil, "10.0.1.200:1")))
	a.False(admitted(server, newSourceConn(nil, "10.0.1.201:1")))
}

func TestHandshakeRateGlobal(t *testing.T) {
	a := require.New(t)
	clk := clock.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	server := newRateServer(
		t, clk,
		ServeWithHandshakeRate(
			RateLimit{}, RateLimit{}, RateLimit{PerSecond: 1, Burst: 3},
		),
	)

	// Every connection is from a network of its own.
	for i := range 4 {
		addr := fmt.Sprintf("10.0.%d.1:1", i)
		a.Equal(
			i < 3, admitted(server, newSourceConn(nil, addr)),
			"admit %d", i,
		)
	}
	clk.Advance(time.Second)
	a.True(admitted(server, newSourceConn(nil, "10.0.9.1:1")))
	a.False(admitted(server, newSourceConn(nil, "10.0.10.1:1")))
}

func TestHandshakeRateAddresslessShareOneBucket(t *testing.T) {
	// An addressless conn, as a relay conn is, and a forgeable one have no
	// source or network key of their own.
	kinds := []struct {
		newConn func(n int) Conn
		name    string
	}{
		{
			name:    "addressless",
			newConn: func(int) Conn { return stubbornConn{} },
		},
		{
			name: "forgeable",
			newConn: func(n int) Conn {
				// Each one claims another host.
				return newUDPSourceConn(
					nil, fmt.Sprintf("10.%d.0.1:1", n),
				)
			},
		},
	}
	for _, third := range kinds {
		t.Run("third is "+third.name, func(t *testing.T) {
			a := require.New(t)
			clk := clock.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
			server := newRateServer(
				t, clk,
				ServeWithHandshakeRate(
					RateLimit{}, RateLimit{PerSecond: 1, Burst: 2},
					RateLimit{},
				),
			)

			a.True(
				admitted(server, kinds[0].newConn(1)),
				"first addressless conn",
			)
			a.True(
				admitted(server, kinds[1].newConn(2)),
				"first forgeable conn",
			)
			a.False(
				admitted(server, third.newConn(3)),
				"third conn shares the bucket",
			)
			a.True(
				admitted(server, newSourceConn(nil, "10.0.0.1:1")),
				"a routable conn shares no bucket with them",
			)

			clk.Advance(time.Second)
			a.True(admitted(server, third.newConn(4)))
			a.False(admitted(server, third.newConn(5)))
		})
	}
}

// TestHandshakeRateForgeableDoesNotDrainRealHost checks that a forgeable
// conn that claims a real host's address uses no token of that host.
func TestHandshakeRateForgeableDoesNotDrainRealHost(t *testing.T) {
	a := require.New(t)
	clk := clock.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	server := newRateServer(t, clk)

	// More than the source and the network allow, all claiming 10.0.0.1.
	for i := range 3 * defaultNetworkRateBurst {
		addr := fmt.Sprintf("10.0.0.1:%d", i+1)
		admitted(server, newUDPSourceConn(nil, addr))
	}
	for i := range defaultSourceRateBurst {
		addr := fmt.Sprintf("10.0.0.1:%d", i+1000)
		a.True(
			admitted(server, newSourceConn(nil, addr)),
			"routable conn %d of the real host", i,
		)
	}
}

func TestHandshakeRateZeroValueTurnsLevelOff(t *testing.T) {
	a := require.New(t)
	clk := clock.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	server := newRateServer(
		t, clk, ServeWithHandshakeRate(RateLimit{}, RateLimit{}, RateLimit{}),
	)

	for i := range 100 {
		addr := fmt.Sprintf("10.0.0.1:%d", i+1)
		a.True(
			admitted(server, newSourceConn(nil, addr)),
			"admit %d", i,
		)
	}
	for i := range 100 {
		a.True(admitted(server, stubbornConn{}), "addressless %d", i)
		a.True(
			admitted(server, newUDPSourceConn(nil, "10.0.0.1:1")),
			"forgeable %d", i,
		)
	}
}

func TestHandshakeRateRejectsInvalidLevel(t *testing.T) {
	good := RateLimit{PerSecond: 1, Burst: 1}
	bad := []struct {
		rate RateLimit
		name string
	}{
		{name: "negative rate", rate: RateLimit{PerSecond: -1, Burst: 1}},
		{name: "negative burst", rate: RateLimit{PerSecond: 1, Burst: -1}},
		{name: "NaN rate", rate: RateLimit{PerSecond: math.NaN(), Burst: 1}},
		{name: "infinite rate", rate: RateLimit{PerSecond: math.Inf(1), Burst: 1}},
		{name: "zero burst", rate: RateLimit{PerSecond: 1}},
		{name: "negative burst without rate", rate: RateLimit{Burst: -5}},
	}
	levels := []string{"source", "network", "global"}

	store, cleanup := newTestStore(t)
	t.Cleanup(cleanup)
	for i, level := range levels {
		for _, tc := range bad {
			t.Run(level+"/"+tc.name, func(t *testing.T) {
				a := require.New(t)
				rates := []RateLimit{good, good, good}
				rates[i] = tc.rate
				_, err := NewServer(
					"",
					func(*Transport) error { return nil },
					store,
					func(
						context.Context, *storage.Storage, VerifyRequest,
					) error {
						return nil
					},
					ServeWithListener(newTestListener(net.ErrClosed)),
					ServeWithHandshakeRate(rates[0], rates[1], rates[2]),
				)
				a.Error(err)
				a.ErrorContains(err, level+" level")
			})
		}
	}
}

func TestHandshakeRateLimitersAreLazy(t *testing.T) {
	cases := []struct {
		name string
		opt  ServerOptions
		// source, network and global are whether each level has a limiter
		// once the server has admitted a connection.
		source, network, global bool
	}{
		{
			name:   "defaults",
			source: true, network: true, global: true,
		},
		{
			name: "all off",
			opt: ServeWithHandshakeRate(
				RateLimit{}, RateLimit{}, RateLimit{},
			),
		},
		{
			name: "only source off",
			opt: ServeWithHandshakeRate(
				RateLimit{}, RateLimit{PerSecond: 1, Burst: 1},
				RateLimit{PerSecond: 1, Burst: 1},
			),
			network: true, global: true,
		},
		{
			name: "only global on",
			opt: ServeWithHandshakeRate(
				RateLimit{}, RateLimit{}, RateLimit{PerSecond: 1, Burst: 1},
			),
			global: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			clk := clock.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
			var opts []ServerOptions
			if tc.opt != nil {
				opts = append(opts, tc.opt)
			}
			server := newRateServer(t, clk, opts...)

			a.Nil(server.limiters, "limiters built before the first admit")
			a.True(admitted(server, newSourceConn(nil, "10.0.0.1:1")))
			a.NotNil(server.limiters)
			a.Equal(tc.source, server.limiters.source != nil, "source")
			a.Equal(tc.network, server.limiters.network != nil, "network")
			a.Equal(tc.global, server.limiters.global != nil, "global")
		})
	}
}

func TestHandshakeRateDefaults(t *testing.T) {
	a := require.New(t)
	server := newRateServer(t, clock.Real())

	a.InDelta(defaultSourceRatePerSecond, server.rates.source.PerSecond, 0)
	a.Equal(defaultSourceRateBurst, server.rates.source.Burst)
	a.InDelta(defaultNetworkRatePerSecond, server.rates.network.PerSecond, 0)
	a.Equal(defaultNetworkRateBurst, server.rates.network.Burst)
	a.GreaterOrEqual(
		server.rates.global.PerSecond, float64(defaultGlobalRatePerCore),
	)
	a.Equal(
		2*int(server.rates.global.PerSecond), server.rates.global.Burst,
	)
}
