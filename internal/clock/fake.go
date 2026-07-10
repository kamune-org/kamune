package clock

import "time"

// Fake is a controllable clock for tests.
type Fake struct {
	now time.Time
}

// NewFake returns a Fake clock set to the given time.
func NewFake(now time.Time) *Fake {
	return &Fake{now: now}
}

func (f *Fake) Now() time.Time          { return f.now }
func (f *Fake) Set(t time.Time)         { f.now = t }
func (f *Fake) Advance(d time.Duration) { f.now = f.now.Add(d) }
