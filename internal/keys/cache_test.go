package keys_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/andreswebs/jwt-authorizer-lambda/internal/keys"
)

// countingFetcher records how often it was called and what it returns next.
type countingFetcher struct {
	mu    sync.Mutex
	calls int
	keys  [][]byte
	err   error
}

func (f *countingFetcher) Fetch(context.Context) ([][]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.keys, f.err
}

func (f *countingFetcher) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *countingFetcher) set(k [][]byte, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys, f.err = k, err
}

func TestCacheFetchesOnceWithinTTL(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	fetcher := &countingFetcher{keys: [][]byte{[]byte("primary")}}
	cache := keys.NewCache[[][]byte](fetcher, time.Minute, func() time.Time { return now })

	for range 5 {
		got, err := cache.Get(context.Background())
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		if len(got) != 1 || string(got[0]) != "primary" {
			t.Fatalf("Get() = %q, want [primary]", got)
		}
	}

	if fetcher.count() != 1 {
		t.Errorf("fetch count = %d, want 1", fetcher.count())
	}
}

func TestCacheRefetchesAfterTTL(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	fetcher := &countingFetcher{keys: [][]byte{[]byte("old")}}
	cache := keys.NewCache[[][]byte](fetcher, time.Minute, func() time.Time { return now })

	if _, err := cache.Get(context.Background()); err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	// A rotation lands, and the clock passes the TTL.
	fetcher.set([][]byte{[]byte("new")}, nil)
	now = now.Add(2 * time.Minute)

	got, err := cache.Get(context.Background())
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if len(got) != 1 || string(got[0]) != "new" {
		t.Errorf("Get() = %q, want [new]; rotated key not picked up", got)
	}
	if fetcher.count() != 2 {
		t.Errorf("fetch count = %d, want 2", fetcher.count())
	}
}

func TestCacheServesStaleWhenRefreshFails(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	fetcher := &countingFetcher{keys: [][]byte{[]byte("primary")}}
	cache := keys.NewCache[[][]byte](fetcher, time.Minute, func() time.Time { return now })

	if _, err := cache.Get(context.Background()); err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	// SSM goes down after the keys were already known good.
	fetcher.set(nil, errors.New("ssm unavailable"))
	now = now.Add(2 * time.Minute)

	got, err := cache.Get(context.Background())
	if err != nil {
		t.Fatalf("Get() error = %v, want nil; a transient outage must not reject valid callers", err)
	}
	if len(got) != 1 || string(got[0]) != "primary" {
		t.Errorf("Get() = %q, want [primary] served from cache", got)
	}
}

func TestCacheReturnsErrorWhenNothingCached(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	fetcher := &countingFetcher{err: errors.New("ssm unavailable")}
	cache := keys.NewCache[[][]byte](fetcher, time.Minute, func() time.Time { return now })

	if _, err := cache.Get(context.Background()); err == nil {
		t.Error("Get() error = nil, want non-nil when no keys were ever retrieved")
	}
}

func TestCacheIsSafeForConcurrentUse(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	fetcher := &countingFetcher{keys: [][]byte{[]byte("primary")}}
	cache := keys.NewCache[[][]byte](fetcher, time.Minute, func() time.Time { return now })

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := cache.Get(context.Background()); err != nil {
				t.Errorf("Get() error = %v", err)
			}
		}()
	}
	wg.Wait()
}
