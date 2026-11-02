package udppath

const (
	// maxCounter is the first counter a DATA or CLOSE may not use.
	maxCounter = uint64(1) << 63

	// windowWords is the bitmap size in 64-bit words. A window of
	// ReplayWindow counters can touch ReplayWindow/64 + 1 words, so the
	// bitmap keeps one more word than RFC 6479's N/64. Without it, the word
	// of the highest counter would also hold counters ReplayWindow behind,
	// and clearing it would let them through again.
	windowWords = ReplayWindow/64 + 1
)

// window is the sliding replay window of one path's receive direction
// (RFC 6479). Only the socket reader uses it.
type window struct {
	bits    [windowWords]uint64
	highest uint64
}

// check reports whether ctr may be accepted. It changes nothing; update
// records ctr once its packet has been opened.
func (w *window) check(ctr uint64) bool {
	switch {
	case ctr == 0 || ctr >= maxCounter:
		return false
	case ctr > w.highest:
		return true
	case ctr+ReplayWindow <= w.highest:
		return false
	}
	return w.bits[(ctr/64)%windowWords]&(1<<(ctr%64)) == 0
}

// update records ctr, which check accepted. A counter above the highest
// slides the window and clears the words it moves past.
func (w *window) update(ctr uint64) {
	if ctr > w.highest {
		cur, next := w.highest/64, ctr/64
		for i := range min(next-cur, windowWords) {
			w.bits[(cur+i+1)%windowWords] = 0
		}
		w.highest = ctr
	}
	w.bits[(ctr/64)%windowWords] |= 1 << (ctr % 64)
}
