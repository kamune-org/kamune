package clock

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFakeConcurrentNowAndAdvance(t *testing.T) {
	a := require.New(t)
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	f := NewFake(start)
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
	a.True(f.Now().Equal(start.Add(100 * time.Second)))
}
