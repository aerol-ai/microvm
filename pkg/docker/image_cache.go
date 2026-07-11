package docker

import (
	"strings"
	"sync"
	"time"
)

// imageIDCacheTTL bounds how long a tag→image-ID resolution is trusted
// without re-asking the engine. The warm-adopt path uses the cached ID to
// validate parked slots, so the TTL is the worst-case staleness window for
// image re-tags done OUT-OF-BAND (docker CLI on the host): within it, an
// adopt can still hand out a slot built from the previous image — the same
// outcome as creating moments before the re-tag. Mutations that go through
// sandboxd itself (pull, build tag, image GC delete) flush the entry
// immediately and never wait on the TTL. Kept short rather than
// events-driven on purpose: /events is label-scoped to managed containers,
// and a second image-event subscription is a reconnect loop we'd have to
// own for a 10-second freshness gain.
const imageIDCacheTTL = 10 * time.Second

type imageCacheEntry struct {
	id      string
	expires time.Time
}

// imageIDCache memoizes image reference → image ID lookups so the warm-adopt
// hot path doesn't pay an engine round-trip (~40ms on small hosts) per
// create. It is metadata-only: a stale or missing entry can never break a
// create, only route it through the slower inspect-or-cold path.
type imageIDCache struct {
	mu      sync.RWMutex
	ttl     time.Duration
	entries map[string]imageCacheEntry
	now     func() time.Time // test seam
}

func newImageIDCache(ttl time.Duration) *imageIDCache {
	return &imageIDCache{
		ttl:     ttl,
		entries: make(map[string]imageCacheEntry),
		now:     time.Now,
	}
}

// All methods are nil-safe: tests (and any future construction path that
// bypasses New) get pass-through behavior — every lookup misses and falls
// back to the engine inspect, never a panic.

func (c *imageIDCache) Get(ref string) (string, bool) {
	if c == nil {
		return "", false
	}
	c.mu.RLock()
	entry, ok := c.entries[ref]
	c.mu.RUnlock()
	if !ok || c.now().After(entry.expires) {
		return "", false
	}
	return entry.id, true
}

func (c *imageIDCache) Put(ref, id string) {
	if c == nil {
		return
	}
	id = strings.TrimSpace(id)
	if ref == "" || id == "" {
		return
	}
	c.mu.Lock()
	c.entries[ref] = imageCacheEntry{id: id, expires: c.now().Add(c.ttl)}
	c.mu.Unlock()
}

// Flush drops the entry for one reference. Called by every sandboxd-driven
// image mutation (pull, build tag, GC delete) so in-band changes are visible
// to the next create immediately.
func (c *imageIDCache) Flush(ref string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	delete(c.entries, ref)
	c.mu.Unlock()
}
