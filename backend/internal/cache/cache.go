// Package cache is the TTL cache with in-flight dedup, ported from
// src/lib/server/cache.ts. Like the original it is a process-wide singleton:
// the point is cross-panel sharing (the metrics panel peeks the kube panel,
// the incident report peeks everything), and passing one instance through
// every constructor would buy nothing but plumbing.
package cache

import (
	"sync"
	"time"
)

type entry struct {
	at   time.Time
	ttl  time.Duration
	data any
	err  error
}

var (
	mu       sync.Mutex
	store    = map[string]*entry{}
	inflight = map[string]*call{}
)

type call struct {
	done chan struct{}
	data any
	err  error
}

// Cached returns the fresh value under key, or runs fn once — concurrent
// callers for the same key share one upstream call. With failTTL > 0 a failure
// is cached briefly too, so a broken upstream is not hammered on every poll.
func Cached[T any](key string, ttl time.Duration, fn func() (T, error), failTTL time.Duration) (T, error) {
	mu.Lock()
	if e, ok := store[key]; ok && time.Since(e.at) < e.ttl {
		mu.Unlock()
		if e.err != nil {
			var zero T
			return zero, e.err
		}
		return e.data.(T), nil
	}
	if c, ok := inflight[key]; ok {
		mu.Unlock()
		<-c.done
		if c.err != nil {
			var zero T
			return zero, c.err
		}
		return c.data.(T), nil
	}
	c := &call{done: make(chan struct{})}
	inflight[key] = c
	mu.Unlock()

	data, err := fn()
	c.data, c.err = data, err

	mu.Lock()
	if err == nil {
		store[key] = &entry{at: time.Now(), ttl: ttl, data: data}
	} else if failTTL > 0 {
		store[key] = &entry{at: time.Now(), ttl: failTTL, err: err}
	}
	delete(inflight, key)
	mu.Unlock()
	close(c.done)
	return data, err
}

// Peek returns the cached value even when stale, matching the TS peekCached.
func Peek[T any](key string) (T, bool) {
	mu.Lock()
	defer mu.Unlock()
	if e, ok := store[key]; ok && e.err == nil {
		if v, ok := e.data.(T); ok {
			return v, true
		}
	}
	var zero T
	return zero, false
}

func Put(key string, ttl time.Duration, data any) {
	mu.Lock()
	defer mu.Unlock()
	store[key] = &entry{at: time.Now(), ttl: ttl, data: data}
}

// Invalidate drops every key with the prefix; "" clears the lot.
func Invalidate(prefix string) {
	mu.Lock()
	defer mu.Unlock()
	for k := range store {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			delete(store, k)
		}
	}
}
