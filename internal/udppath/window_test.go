package udppath

import (
	"math/rand/v2"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWindow(t *testing.T) {
	type step struct {
		ctr    uint64
		accept bool
	}
	tests := []struct {
		name  string
		steps []step
	}{
		{"in order", []step{{1, true}, {2, true}, {3, true}}},
		{"replay", []step{{1, true}, {2, true}, {2, false}, {1, false}}},
		{"counter range", []step{
			{0, false}, {maxCounter, false}, {maxCounter - 1, true},
		}},
		{"out of order within the window", []step{
			{10, true}, {5, true}, {5, false}, {9, true}, {10, false},
		}},
		{"older than the window", []step{
			{3000, true},
			{3000 - ReplayWindow, false},
			{3000 - ReplayWindow + 1, true},
		}},
		{"far jump slides the window", []step{
			{1, true},
			{100_000, true},
			{1, false},
			{100_000 - ReplayWindow + 1, true},
			{100_000, false},
			{99_999, true},
		}},
		// The word of the new highest counter also held counters a full
		// window behind it. Clearing that word must not readmit them.
		{"edge of the window after a jump", []step{
			{2049, true}, {4096, true}, {2049, false}, {2048, false},
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			var w window
			for i, s := range tc.steps {
				got := w.check(s.ctr)
				a.Equal(s.accept, got, "step %d, counter %d", i, s.ctr)
				if got {
					w.update(s.ctr)
				}
			}
		})
	}
}

// TestWindowMatchesModel checks the bitmap against a set of every counter
// accepted so far.
func TestWindowMatchesModel(t *testing.T) {
	a := require.New(t)
	rng := rand.New(rand.NewPCG(1, 2))
	var w window
	seen := make(map[uint64]bool)
	var highest uint64
	for i := range 200_000 {
		var ctr uint64
		switch rng.IntN(10) {
		case 0:
			ctr = highest + 1 + uint64(rng.IntN(5000))
		default:
			ctr = highest + 50 - uint64(rng.IntN(2200))
		}
		if ctr > maxCounter {
			// highest + 50 - n wrapped below zero.
			ctr = uint64(rng.IntN(50)) + 1
		}
		want := ctr != 0 && ctr < maxCounter && !seen[ctr] &&
			ctr+ReplayWindow > highest
		got := w.check(ctr)
		a.Equal(want, got, "step %d, counter %d, highest %d", i, ctr, highest)
		if got {
			w.update(ctr)
			seen[ctr] = true
			highest = max(highest, ctr)
		}
	}
}
