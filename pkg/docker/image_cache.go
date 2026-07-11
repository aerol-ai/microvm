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
//
// The Client-owned warm loop (see StartImageIDCacheWarmer) re-Puts every
// pool-eligible ref on a cadence shorter than this TTL so sparse creates
// always hit; Flush bumps a per-ref generation so a warm Put that raced an
// in-band mutation is dropped instead of re-installing a stale ID.
const imageIDCacheTTL = 10 * time.Second

// generationGCGrace is how long a flushed ref's generation survives after its
// last bump before Prune may drop it. The fence exists to kill warm Puts that
// snapshotted a pre-Flush generation, and any such Put is in flight for
// seconds (bounded by the inspect round-trip) — never an hour. Dropping a
// generation sooner could let a stale in-flight Put match the zero-value
// generation and re-install a dead ID.
const generationGCGrace = time.Hour

type imageCacheEntry struct {
	id         string
	expires    time.Time
	generation uint64
}

type imageCacheGeneration struct {
	gen    uint64
	bumped time.Time
}

// imageIDCache memoizes image reference → image ID lookups so the warm-adopt
// hot path doesn't pay an engine round-trip (~40ms on small hosts) per
// create. It is metadata-only: a stale or missing entry can never break a
// create, only route it through the slower inspect-or-cold path.
type imageIDCache struct {
	mu          sync.RWMutex
	ttl         time.Duration
	entries     map[string]imageCacheEntry
	generations map[string]imageCacheGeneration // bumped by Flush; PutIfGeneration fences warm Puts
	now         func() time.Time                // test seam
}

func newImageIDCache(ttl time.Duration) *imageIDCache {
	return &imageIDCache{
		ttl:         ttl,
		entries:     make(map[string]imageCacheEntry),
		generations: make(map[string]imageCacheGeneration),
		now:         time.Now,
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

// Generation returns the current Flush generation for ref. Warm loops
// snapshot this before inspect and pass it to PutIfGeneration so a Flush
// that lands mid-inspect drops the stale Put.
func (c *imageIDCache) Generation(ref string) uint64 {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.generations[ref].gen
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
	c.entries[ref] = imageCacheEntry{
		id:         id,
		expires:    c.now().Add(c.ttl),
		generation: c.generations[ref].gen,
	}
	c.mu.Unlock()
}

// PutIfGeneration installs id only when the Flush generation still matches
// the snapshot taken before the warm inspect. Boot-path Put is unaffected.
func (c *imageIDCache) PutIfGeneration(ref, id string, gen uint64) bool {
	if c == nil {
		return false
	}
	id = strings.TrimSpace(id)
	if ref == "" || id == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.generations[ref].gen != gen {
		return false
	}
	c.entries[ref] = imageCacheEntry{
		id:         id,
		expires:    c.now().Add(c.ttl),
		generation: gen,
	}
	return true
}

// Flush drops the entry for one reference and bumps its generation so any
// in-flight warm Put for the previous generation is dropped. Called by every
// sandboxd-driven image mutation (pull, build tag, GC delete) so in-band
// changes are visible to the next create immediately. Piggybacks a prune so
// hosts cycling many unique refs (per-build image tags + GC) don't
// accumulate dead entries and generations forever.
func (c *imageIDCache) Flush(ref string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	delete(c.entries, ref)
	g := c.generations[ref]
	g.gen++
	g.bumped = c.now()
	c.generations[ref] = g
	c.pruneLocked()
	c.mu.Unlock()
}

// Prune drops expired entries and generation fences whose grace elapsed. The
// warm loop calls it once per tick; Flush calls it inline. Both maps stay
// bounded by the live working set plus refs flushed within the last
// generationGCGrace.
func (c *imageIDCache) Prune() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.pruneLocked()
	c.mu.Unlock()
}

func (c *imageIDCache) pruneLocked() {
	now := c.now()
	for ref, e := range c.entries {
		if now.After(e.expires) {
			delete(c.entries, ref)
		}
	}
	for ref, g := range c.generations {
		if _, live := c.entries[ref]; live {
			// A live entry still references this generation; keep the fence.
			continue
		}
		if now.Sub(g.bumped) > generationGCGrace {
			delete(c.generations, ref)
		}
	}
}
