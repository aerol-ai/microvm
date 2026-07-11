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
	if id, ok := c.Get("alpine:3.20"); ok || id != "" {
		t.Fatalf("nil cache Get = %q, %v; want miss", id, ok)
	}
	if c.Generation("alpine:3.20") != 0 {
		t.Fatal("nil cache Generation must be 0")
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
