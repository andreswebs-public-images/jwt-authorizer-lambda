// Package keys supplies the values an authorizer needs at request time and
// caches them, so that every request does not become a parameter-store lookup.
//
// The values are the signing keys and the expected issuer. Both can change
// without a redeploy, and both are read the same way, so both use the same
// cache.
package keys

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Fetcher retrieves a value from its source of truth.
type Fetcher[T any] interface {
	Fetch(ctx context.Context) (T, error)
}

// Provider supplies a value to a caller that does not care where it came from.
type Provider[T any] interface {
	Get(ctx context.Context) (T, error)
}

// Cache memoises a Fetcher for a fixed duration.
//
// A Cache is safe for concurrent use.
type Cache[T any] struct {
	fetcher Fetcher[T]
	ttl     time.Duration
	now     func() time.Time

	mu        sync.Mutex
	value     T
	fetchedAt time.Time
	loaded    bool
}

// NewCache returns a Cache serving fetcher's value for ttl between refreshes.
// A non-positive ttl fetches on every call. now may be nil, meaning time.Now.
func NewCache[T any](fetcher Fetcher[T], ttl time.Duration, now func() time.Time) *Cache[T] {
	if now == nil {
		now = time.Now
	}
	return &Cache[T]{fetcher: fetcher, ttl: ttl, now: now}
}

// Get returns the cached value, refreshing it if it has expired.
//
// If a refresh fails but a value was retrieved successfully at some earlier
// point, the cached value is returned and the error is discarded. The
// alternative is to reject every caller for the duration of a parameter-store
// outage, which turns a dependency's bad minute into dropped events. These
// values change rarely; the stale one is almost certainly still correct.
func (c *Cache[T]) Get(ctx context.Context) (T, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.loaded && c.now().Sub(c.fetchedAt) < c.ttl {
		return c.value, nil
	}

	fetched, err := c.fetcher.Fetch(ctx)
	if err != nil {
		if c.loaded {
			return c.value, nil
		}
		var zero T
		return zero, fmt.Errorf("fetching value: %w", err)
	}

	c.value = fetched
	c.fetchedAt = c.now()
	c.loaded = true

	return c.value, nil
}

// Static is a Provider returning a fixed value, for configuration supplied
// directly rather than looked up.
type Static[T any] struct {
	value T
}

// NewStatic returns a Provider that always yields value.
func NewStatic[T any](value T) Static[T] {
	return Static[T]{value: value}
}

// Get returns the fixed value.
func (s Static[T]) Get(context.Context) (T, error) { return s.value, nil }
