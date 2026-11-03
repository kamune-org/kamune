package udppath

import "math/rand/v2"

// victimLocked picks the path that a new INIT from the network nk evicts at a
// cap. It counts the paths of each network in scope, with the new INIT in nk,
// and takes the networks with the most. When that most is below two, no
// network holds a path that may go, and it returns nil: the INIT is refused.
// Otherwise it picks one of those networks at random and returns its oldest
// path in scope. In pending scope that is its oldest HALF_OPEN path, or else
// its oldest QUEUED path. In all scope it is its oldest path of any state.
// exclude is a path already chosen for removal, and it is not counted. The
// caller holds mu.
func (s *Server) victimLocked(
	pendingOnly bool, nk string, exclude *Path,
) *Path {
	counts := map[string]int{nk: 1}
	for _, p := range s.paths {
		if p == exclude || (pendingOnly && p.entry.state == stateAccepted) {
			continue
		}
		counts[p.entry.network]++
	}
	most := 0
	for _, c := range counts {
		most = max(most, c)
	}
	if most < 2 {
		return nil
	}
	var top []string
	for network, c := range counts {
		if c == most {
			top = append(top, network)
		}
	}
	pick := top[rand.IntN(len(top))]
	var queued *Path
	for _, p := range s.paths {
		if p == exclude || p.entry.network != pick {
			continue
		}
		switch {
		case !pendingOnly:
			return p
		case p.entry.state == stateHalfOpen:
			return p
		case p.entry.state == stateQueued && queued == nil:
			queued = p
		}
	}
	return queued
}
