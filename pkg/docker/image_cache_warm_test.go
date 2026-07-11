package docker

import (
	"context"
	"log/slog"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/pool/dockerpool"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestStartImageIDCacheWarmerRejectsIntervalGTETTL(t *testing.T) {
	c := &Client{imageIDs: newImageIDCache(imageIDCacheTTL)}
	pool := dockerpool.New(slog.Default())
	pool.PinTarget(dockerpool.Key{Image: "alpine:3.20", Runtime: models.RuntimeDocker})

	// Must not panic / start a loop when misconfigured.
	c.StartImageIDCacheWarmer(context.Background(), pool, imageIDCacheTTL, slog.Default())
	c.StartImageIDCacheWarmer(context.Background(), pool, imageIDCacheTTL+time.Second, slog.Default())
	c.StartImageIDCacheWarmer(context.Background(), nil, time.Second, slog.Default())
}

func TestWarmImageIDCacheOnceRetagFreshness(t *testing.T) {
	var id atomic.Value
	id.Store("sha256:v1")
	d := &poolFakeDaemon{t: t, imageInspect: func() *http.Response {
		return jsonResponse(http.StatusOK, map[string]any{"Id": id.Load().(string)})
	}}
	c := newPoolClient(t, d, func(c *Client) {
		c.imageIDs = newImageIDCache(time.Minute)
	})
	pool := dockerpool.New(slog.Default())
	pool.PinTarget(dockerpool.Key{Image: "alpine:3.20", Runtime: models.RuntimeDocker})

	c.warmImageIDCacheOnce(context.Background(), pool, slog.Default())
	if got, ok := c.imageIDs.Get("alpine:3.20"); !ok || got != "sha256:v1" {
		t.Fatalf("first warm = %q, %v", got, ok)
	}

	id.Store("sha256:v2")
	c.warmImageIDCacheOnce(context.Background(), pool, slog.Default())
	if got, ok := c.imageIDs.Get("alpine:3.20"); !ok || got != "sha256:v2" {
		t.Fatalf("retag warm = %q, %v; want sha256:v2 within one tick", got, ok)
	}
}

func TestWarmImageIDCacheOnceFlushFence(t *testing.T) {
	d := &poolFakeDaemon{t: t, imageInspect: func() *http.Response {
		return jsonResponse(http.StatusOK, map[string]any{"Id": "sha256:new"})
	}}
	c := newPoolClient(t, d, func(c *Client) {
		c.imageIDs = newImageIDCache(time.Minute)
	})
	pool := dockerpool.New(slog.Default())
	pool.PinTarget(dockerpool.Key{Image: "alpine:3.20", Runtime: models.RuntimeDocker})

	gen := c.imageIDs.Generation("alpine:3.20")
	c.imageIDs.Flush("alpine:3.20")
	if c.imageIDs.PutIfGeneration("alpine:3.20", "sha256:old", gen) {
		t.Fatal("stale warm Put must be dropped after Flush")
	}

	c.warmImageIDCacheOnce(context.Background(), pool, slog.Default())
	if got, hit := c.imageIDs.Get("alpine:3.20"); !hit || got != "sha256:new" {
		t.Fatalf("next tick = %q, %v; want fresh id", got, hit)
	}
}

func TestResolveImageIDForWarmNoTimingStage(t *testing.T) {
	d := &poolFakeDaemon{t: t, imageInspect: func() *http.Response {
		return jsonResponse(http.StatusOK, map[string]any{"Id": "sha256:abc"})
	}}
	c := newPoolClient(t, d, func(c *Client) {
		c.imageIDs = newImageIDCache(time.Minute)
	})

	// Background ctx has no CreateTiming — must not panic / record a stage.
	id, ok, err := c.resolveImageIDForWarm(context.Background(), "alpine:3.20")
	if err != nil || !ok || id != "sha256:abc" {
		t.Fatalf("resolveImageIDForWarm = %q, %v, %v", id, ok, err)
	}
}

func TestRunImageIDCacheWarmerTickerAndCancel(t *testing.T) {
	var inspects atomic.Int64
	d := &poolFakeDaemon{t: t, imageInspect: func() *http.Response {
		inspects.Add(1)
		return jsonResponse(http.StatusOK, map[string]any{"Id": "sha256:tick"})
	}}
	c := newPoolClient(t, d, func(c *Client) {
		c.imageIDs = newImageIDCache(time.Minute)
	})
	pool := dockerpool.New(slog.Default())
	pool.PinTarget(dockerpool.Key{Image: "alpine:3.20", Runtime: models.RuntimeDocker})
	pool.PinTarget(dockerpool.Key{Image: "", Runtime: models.RuntimeDocker}) // skipped

	ctx, cancel := context.WithCancel(context.Background())
	c.StartImageIDCacheWarmer(ctx, pool, 20*time.Millisecond, slog.Default())

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && inspects.Load() < 2 {
		time.Sleep(10 * time.Millisecond)
	}
	if inspects.Load() < 2 {
		t.Fatalf("inspects = %d, want ≥2 (immediate warm + ticker)", inspects.Load())
	}
	cancel()
	time.Sleep(50 * time.Millisecond) // let goroutine exit
}

func TestWarmImageIDCacheOnceErrorAndStalePaths(t *testing.T) {
	d := &poolFakeDaemon{t: t, imageInspect: func() *http.Response {
		return jsonResponse(http.StatusNotFound, map[string]any{"message": "missing"})
	}}
	c := newPoolClient(t, d, func(c *Client) {
		c.imageIDs = newImageIDCache(time.Minute)
	})
	pool := dockerpool.New(slog.Default())
	pool.PinTarget(dockerpool.Key{Image: "gone:latest", Runtime: models.RuntimeDocker})

	// Error path logs and continues — must not panic.
	c.warmImageIDCacheOnce(context.Background(), pool, slog.Default())

	// Nil guards.
	c.warmImageIDCacheOnce(context.Background(), nil, slog.Default())
	var nilClient *Client
	nilClient.warmImageIDCacheOnce(context.Background(), pool, slog.Default())

	// Stale put path: Flush mid-inspect so PutIfGeneration drops the warm install.
	var cStale *Client
	dStale := &poolFakeDaemon{t: t, imageInspect: func() *http.Response {
		cStale.imageIDs.Flush("stale:latest")
		return jsonResponse(http.StatusOK, map[string]any{"Id": "sha256:stale"})
	}}
	cStale = newPoolClient(t, dStale, func(c *Client) {
		c.imageIDs = newImageIDCache(time.Minute)
	})
	poolStale := dockerpool.New(slog.Default())
	poolStale.PinTarget(dockerpool.Key{Image: "stale:latest", Runtime: models.RuntimeDocker})
	cStale.warmImageIDCacheOnce(context.Background(), poolStale, slog.Default())
	if _, ok := cStale.imageIDs.Get("stale:latest"); ok {
		t.Fatal("stale warm Put must be dropped when Flush races inspect")
	}
}
