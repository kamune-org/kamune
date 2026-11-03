package udppath

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVictimLocked(t *testing.T) {
	type spec struct {
		network string
		state   pathState
	}
	tests := []struct {
		name        string
		paths       []spec
		exclude     int
		newNetwork  string
		pendingOnly bool
		// want is the index of the expected victim in paths, or -1 for none.
		want int
	}{
		{
			name: "one path per network refuses",
			paths: []spec{
				{"A", stateHalfOpen}, {"B", stateHalfOpen},
			},
			exclude: -1, newNetwork: "C", pendingOnly: true, want: -1,
		},
		{
			name: "largest network, oldest half open",
			paths: []spec{
				{"A", stateQueued}, {"B", stateHalfOpen},
				{"A", stateHalfOpen}, {"C", stateHalfOpen},
			},
			exclude: -1, newNetwork: "D", pendingOnly: true, want: 2,
		},
		{
			name: "pending scope skips accepted",
			paths: []spec{
				{"A", stateAccepted}, {"A", stateQueued},
				{"B", stateHalfOpen}, {"B", stateHalfOpen},
			},
			exclude: -1, newNetwork: "C", pendingOnly: true, want: 2,
		},
		{
			name: "pending scope with only accepted paths refuses",
			paths: []spec{
				{"A", stateAccepted}, {"A", stateAccepted},
				{"B", stateHalfOpen},
			},
			exclude: -1, newNetwork: "C", pendingOnly: true, want: -1,
		},
		{
			name: "queued when no half open",
			paths: []spec{
				{"A", stateQueued}, {"A", stateQueued},
			},
			exclude: -1, newNetwork: "B", pendingOnly: true, want: 0,
		},
		{
			name: "all scope takes the oldest of any state",
			paths: []spec{
				{"A", stateAccepted}, {"A", stateHalfOpen},
				{"B", stateHalfOpen},
			},
			exclude: -1, newNetwork: "C", pendingOnly: false, want: 0,
		},
		{
			name: "the new INIT counts in its own network",
			paths: []spec{
				{"A", stateHalfOpen}, {"B", stateHalfOpen},
			},
			exclude: -1, newNetwork: "A", pendingOnly: true, want: 0,
		},
		{
			name: "an excluded path is not counted",
			paths: []spec{
				{"A", stateHalfOpen}, {"A", stateHalfOpen},
			},
			exclude: 0, newNetwork: "C", pendingOnly: false, want: -1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			s := &Server{}
			for _, sp := range tc.paths {
				s.paths = append(s.paths, &Path{entry: &serverEntry{
					network: sp.network,
					state:   sp.state,
				}})
			}
			var exclude *Path
			if tc.exclude >= 0 {
				exclude = s.paths[tc.exclude]
			}
			got := s.victimLocked(tc.pendingOnly, tc.newNetwork, exclude)
			if tc.want < 0 {
				a.Nil(got)
				return
			}
			a.NotNil(got)
			a.Same(s.paths[tc.want], got)
		})
	}
}
