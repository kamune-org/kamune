// Package cmap provides a concurrent map with type checking at compile time.
package cmap

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"maps"
	"slices"
	"sync"
	"time"
)

var (
	ErrMissing = errors.New("does not exist")
)

type ConcurrentMap[T comparable, S any] struct {
	m  map[T]S
	mu sync.RWMutex
}

func New[T comparable, S any]() *ConcurrentMap[T, S] {
	return &ConcurrentMap[T, S]{m: make(map[T]S)}
}

func (c *ConcurrentMap[T, S]) Add(key T, value S) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[key] = value
}

func (c *ConcurrentMap[T, S]) Remove(key T) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, key)
}

func (c *ConcurrentMap[T, S]) Get(key T) (S, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	value, ok := c.m[key]
	return value, ok
}

func (c *ConcurrentMap[T, S]) Exists(key T) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.m[key]
	return ok
}

func (c *ConcurrentMap[T, S]) Put(key T, f func(element S) (S, error)) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.m[key]; !ok {
		return ErrMissing
	}
	value, err := f(c.m[key])
	if err != nil {
		return err
	}
	c.m[key] = value
	return nil
}

func (c *ConcurrentMap[T, S]) Keys() []T {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return slices.Collect(maps.Keys(c.m))
}

func (c *ConcurrentMap[T, S]) Values() []S {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return slices.Collect(maps.Values(c.m))
}

// Iter returns an iterator over the map. It is not safe for concurrent calls,
// as it doesn't acquire a read or write lock.
func (c *ConcurrentMap[T, S]) Iter() iter.Seq2[T, S] {
	return func(yield func(T, S) bool) {
		for k, v := range c.m {
			if !yield(k, v) {
				return
			}
		}
	}
}

func (c *ConcurrentMap[T, S]) CleanUp(
	ctx context.Context, interval time.Duration, isUsed func(T, S) bool,
) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			func() {
				c.mu.Lock()
				defer c.mu.Unlock()
				for k, v := range c.Iter() {
					if !isUsed(k, v) {
						c.Remove(k)
					}
				}
			}()
		}
	}
}

func (c *ConcurrentMap[T, S]) String() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return fmt.Sprintf("%v", c.m)
}
