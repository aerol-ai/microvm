package docker

import (
	"testing"
	"time"
)

func TestImageIDCachePutGetFlush(t *testing.T) {
	c := newImageIDCache(time.Minute)

	if id, ok := c.Get("alpine:3.20"); ok || id != "" {
		t.Fatalf("Get on empty cache = %q, %v; want miss", id, ok)
	}

	c.Put("alpine:3.20", " sha256:abc ")
	id, ok := c.Get("alpine:3.20")
	if !ok || id != "sha256:abc" {
		t.Fatalf("Get after Put = %q, %v; want trimmed sha256:abc hit", id, ok)
	}

	c.Flush("alpine:3.20")
	if _, ok := c.Get("alpine:3.20"); ok {
		t.Fatal("Get after Flush should miss")
	}

	// Degenerate inputs never poison the cache.
	c.Put("", "sha256:abc")
	c.Put("alpine:3.20", "")
	if _, ok := c.Get(""); ok {
		t.Fatal("empty ref should never be cached")
	}
	if _, ok := c.Get("alpine:3.20"); ok {
		t.Fatal("empty id should never be cached")
	}
}

func TestImageIDCacheTTLExpiry(t *testing.T) {
	c := newImageIDCache(10 * time.Second)
	current := time.Unix(1000, 0)
	c.now = func() time.Time { return current }

	c.Put("alpine:3.20", "sha256:abc")
	if _, ok := c.Get("alpine:3.20"); !ok {
		t.Fatal("fresh entry should hit")
	}

	current = current.Add(9 * time.Second)
	if _, ok := c.Get("alpine:3.20"); !ok {
		t.Fatal("entry inside TTL should hit")
	}

	current = current.Add(2 * time.Second)
	if id, ok := c.Get("alpine:3.20"); ok {
		t.Fatalf("entry past TTL should miss, got %q", id)
	}

	// A re-Put after expiry starts a fresh TTL window.
	c.Put("alpine:3.20", "sha256:def")
	if id, ok := c.Get("alpine:3.20"); !ok || id != "sha256:def" {
		t.Fatalf("re-Put after expiry = %q, %v; want sha256:def hit", id, ok)
	}
}

// A nil cache is pass-through, never a panic: tests and any construction
// path that bypasses New must fall back to the engine inspect.
func TestImageIDCacheNilSafe(t *testing.T) {
	var c *imageIDCache
	c.Put("alpine:3.20", "sha256:abc")
	c.PutIfGeneration("alpine:3.20", "sha256:abc", 0)
	c.Flush("alpine:3.20")
	c.Prune()
	if id, ok := c.Get("alpine:3.20"); ok || id != "" {
		t.Fatalf("nil cache Get = %q, %v; want miss", id, ok)
	}
	if c.Generation("alpine:3.20") != 0 {
		t.Fatal("nil cache Generation must be 0")
	}
}

// Hosts that cycle unique refs (per-build tags + image GC) must not grow the
// cache maps forever: expired entries prune immediately; generation fences
// prune only after generationGCGrace so an in-flight warm Put can never match
// a reset fence.
func TestImageIDCachePruneBoundsGrowth(t *testing.T) {
	c := newImageIDCache(10 * time.Second)
	current := time.Unix(1000, 0)
	c.now = func() time.Time { return current }

	for _, ref := range []string{"build:a", "build:b", "build:c"} {
		c.Put(ref, "sha256:"+ref)
		c.Flush(ref) // simulates GC delete; installs a generation fence
	}
	if len(c.entries) != 0 {
		t.Fatalf("entries after flush = %d, want 0", len(c.entries))
	}
	if len(c.generations) != 3 {
		t.Fatalf("generations = %d, want 3 fences", len(c.generations))
	}

	// Inside the grace window the fence must survive a prune and still drop
	// a warm Put that snapshotted the pre-Flush generation.
	current = current.Add(30 * time.Minute)
	c.Prune()
	if len(c.generations) != 3 {
		t.Fatalf("generations pruned inside grace = %d, want 3", len(c.generations))
	}
	if c.PutIfGeneration("build:a", "sha256:stale", 0) {
		t.Fatal("stale warm Put must be fenced while the generation survives")
	}

	// Past the grace the fences go; an expired live entry goes with them.
	c.Put("expired:ref", "sha256:x")
	current = current.Add(generationGCGrace + time.Minute)
	c.Prune()
	if len(c.generations) != 0 {
		t.Fatalf("generations after grace = %d, want 0", len(c.generations))
	}
	if len(c.entries) != 0 {
		t.Fatalf("entries after prune = %d, want 0 (expired:ref lapsed)", len(c.entries))
	}

	// A ref with a LIVE entry keeps its fence regardless of age.
	c.Put("live:ref", "sha256:y")
	c.Flush("live:ref")
	c.Put("live:ref", "sha256:z")
	current = current.Add(generationGCGrace + time.Minute)
	// Keep the entry unexpired for this check: re-put refreshes the TTL.
	c.Put("live:ref", "sha256:z")
	c.Prune()
	if _, ok := c.generations["live:ref"]; !ok {
		t.Fatal("generation with a live entry must survive prune")
	}
}

func TestImageIDCacheFlushGenerationFence(t *testing.T) {
	c := newImageIDCache(time.Minute)
	gen := c.Generation("alpine:3.20")
	c.PutIfGeneration("alpine:3.20", "sha256:old", gen)
	if id, ok := c.Get("alpine:3.20"); !ok || id != "sha256:old" {
		t.Fatalf("seed PutIfGeneration = %q, %v", id, ok)
	}

	// Flush between warm snapshot and Put drops the stale install.
	c.Flush("alpine:3.20")
	if c.PutIfGeneration("alpine:3.20", "sha256:stale", gen) {
		t.Fatal("PutIfGeneration must drop after Flush bumped generation")
	}
	if _, ok := c.Get("alpine:3.20"); ok {
		t.Fatal("stale Put must not re-install after Flush")
	}

	// Next warm tick (fresh generation) installs cleanly.
	gen2 := c.Generation("alpine:3.20")
	if gen2 == gen {
		t.Fatal("Flush must bump generation")
	}
	if !c.PutIfGeneration("alpine:3.20", "sha256:fresh", gen2) {
		t.Fatal("fresh generation PutIfGeneration must succeed")
	}
	if id, ok := c.Get("alpine:3.20"); !ok || id != "sha256:fresh" {
		t.Fatalf("Get after fresh Put = %q, %v", id, ok)
	}

	// Empty id / ref are rejected the same way Put rejects them.
	if c.PutIfGeneration("alpine:3.20", "  ", gen2) {
		t.Fatal("blank id must be rejected")
	}
	if c.PutIfGeneration("", "sha256:x", gen2) {
		t.Fatal("empty ref must be rejected")
	}
}

func TestImageIDCacheWarmAcrossSparseGap(t *testing.T) {
	c := newImageIDCache(10 * time.Second)
	current := time.Unix(1000, 0)
	c.now = func() time.Time { return current }

	// Simulate warm ticks every 5s across a 15s+ sparse gap.
	for i := 0; i < 4; i++ {
		c.Put("alpine:3.20", "sha256:abc")
		current = current.Add(5 * time.Second)
	}
	// After 20s wall time with refreshes every 5s, entry must still hit.
	if id, ok := c.Get("alpine:3.20"); !ok || id != "sha256:abc" {
		t.Fatalf("warm-across-sparse-gap Get = %q, %v; want hit", id, ok)
	}
}
