package clock

import (
	"sync"
	"testing"
	"time"
)

func TestFakeConcurrentNowAndAdvance(t *testing.T) {
	f := NewFake(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 100 {
			f.Advance(time.Second)
		}
	}()
	go func() {
		defer wg.Done()
		for range 100 {
			f.Now()
		}
	}()
	wg.Wait()
}
