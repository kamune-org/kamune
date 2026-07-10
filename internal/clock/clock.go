package clock

import "time"

// Clock abstracts time for testing and determinism.
type Clock interface {
	Now() time.Time
}

// Real returns a Clock backed by the system clock.
func Real() Clock { return realClock{} }

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }
