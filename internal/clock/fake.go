package clock

import (
	"sync"
	"time"
)

// Fake is a controllable clock for tests.
type Fake struct {
	now time.Time
	mu  sync.Mutex
}

// NewFake returns a Fake clock set to the given time.
func NewFake(now time.Time) *Fake {
	return &Fake{now: now}
}

func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *Fake) Set(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = t
}

func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}
