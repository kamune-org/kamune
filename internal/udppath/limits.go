package udppath

import (
	"fmt"

	"github.com/kamune-org/kamune/internal/admit"
)

// Defaults of the server limits. A zero field of [Limits] takes its default.
const (
	defaultMaxPaths         = 4096
	defaultPathsPerSource   = 32
	defaultPathsPerNetwork  = 128
	defaultMaxPending       = 256
	defaultPendingPerSource = 4
	defaultInitPerSecond    = 4
	defaultInitBurst        = 8

	// initSlots is the bucket count of the per-source INIT limiter. Two
	// sources that share a bucket share its tokens, which is stricter, never
	// looser.
	initSlots = 16384
)

// Limits bounds what a [Server] keeps and admits. A zero field takes its
// default. A negative value means no limit, and is allowed only for
// MaxPathsPerSource, MaxPathsPerNetwork and MaxPendingPerSource.
type Limits struct {
	// InitRate is how many INITs per second one source may send, and its
	// burst. The zero value is {PerSecond: 4, Burst: 8}. Any other value must
	// pass [admit.Rate.Validate], and a PerSecond of zero turns the limit off.
	InitRate admit.Rate

	// MaxPaths caps the paths in every state, default 4096. At the cap, a new
	// INIT evicts the oldest path of the network with the most paths.
	MaxPaths int

	// MaxPathsPerSource caps the paths of one source address, which for IPv6
	// is a /64. The default is 32.
	MaxPathsPerSource int

	// MaxPathsPerNetwork caps the paths of one network, which is an IPv4 /24
	// or an IPv6 /48. The default is 128.
	MaxPathsPerNetwork int

	// MaxPending caps the HALF_OPEN and QUEUED paths, default 256. At the
	// cap, a new INIT evicts a pending path of the network with the most.
	MaxPending int

	// MaxPendingPerSource caps the HALF_OPEN and QUEUED paths of one source,
	// default 4.
	MaxPendingPerSource int
}

// resolvedLimits is a [Limits] with its defaults applied. A negative
// per-source or per-network value stays negative and means no limit.
type resolvedLimits struct {
	initRate            admit.Rate
	maxPaths            int
	maxPathsPerSource   int
	maxPathsPerNetwork  int
	maxPending          int
	maxPendingPerSource int
}

// resolve applies the defaults. It fails for a negative MaxPaths or
// MaxPending, and for an InitRate that does not validate.
func (l Limits) resolve() (resolvedLimits, error) {
	switch {
	case l.MaxPaths < 0:
		return resolvedLimits{}, fmt.Errorf(
			"udp path: MaxPaths is negative: %d", l.MaxPaths,
		)
	case l.MaxPending < 0:
		return resolvedLimits{}, fmt.Errorf(
			"udp path: MaxPending is negative: %d", l.MaxPending,
		)
	}
	r := resolvedLimits{
		initRate: l.InitRate,
		maxPaths: orDefault(l.MaxPaths, defaultMaxPaths),
		maxPathsPerSource: orDefault(
			l.MaxPathsPerSource, defaultPathsPerSource,
		),
		maxPathsPerNetwork: orDefault(
			l.MaxPathsPerNetwork, defaultPathsPerNetwork,
		),
		maxPending: orDefault(l.MaxPending, defaultMaxPending),
		maxPendingPerSource: orDefault(
			l.MaxPendingPerSource, defaultPendingPerSource,
		),
	}
	if l.InitRate == (admit.Rate{}) {
		r.initRate = admit.Rate{
			PerSecond: defaultInitPerSecond,
			Burst:     defaultInitBurst,
		}
	}
	if err := r.initRate.Validate(); err != nil {
		return resolvedLimits{}, fmt.Errorf("udp path: InitRate: %w", err)
	}
	return r, nil
}

// orDefault returns v, or def when v is zero.
func orDefault(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}
