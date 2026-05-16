package service

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

// makeScalePlacements builds a synthetic placement set sized for fleet-scale
// reconciler tests. Each placement is owned by an arbitrary remote node and
// carries one HTTP port and one TCP port — enough to exercise both the
// per-sandbox hash contribution and the per-port hash + counter paths without
// drowning the test in unrealistic per-sandbox fan-out (a 10K-sandbox fleet
// with 50 ports each isn't a shape we operate against).
func makeScalePlacements(n int) []cluster.Placement {
	out := make([]cluster.Placement, n)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("sb-%07d", i)
		out[i] = cluster.Placement{
			SandboxID:          id,
			OwnerNodeID:        fmt.Sprintf("node-%03d", i%32),
			OwnerAPIURL:        fmt.Sprintf("http://10.0.%d.%d:21212", (i/256)%256, i%256),
			OwnerDataPlaneHost: fmt.Sprintf("10.0.%d.%d", (i/256)%256, i%256),
			Version:            uint64(i + 1),
			ExposedPortRoutes: map[int]cluster.ExposedPortRoute{
				3000: {Protocol: models.ExposedPortProtocolHTTP},
				5432: {Protocol: models.ExposedPortProtocolTCP, HostPort: 22000 + i},
			},
		}
	}
	return out
}

// TestHashPlacementViewAt10KIsStable is the steady-state idle-skip claim at
// fleet scale: with 10K placements unchanged between ticks, the reconciler
// must produce the same hash and the same per-protocol counters — otherwise
// the reconciler would push ~30K Caddy admin calls every tick instead of
// returning early. Also logs the wall-clock so a future regression that
// turns hashing super-linear shows up in CI output.
func TestHashPlacementViewAt10KIsStable(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test skipped under -short")
	}
	placements := makeScalePlacements(10_000)

	t0 := time.Now()
	h1, c1, v1 := hashPlacementView("ingress-self", placements)
	first := time.Since(t0)

	t1 := time.Now()
	h2, c2, v2 := hashPlacementView("ingress-self", placements)
	second := time.Since(t1)

	if h1 != h2 {
		t.Fatalf("hash changed across identical calls: %x vs %x", h1, h2)
	}
	if c1 != c2 {
		t.Fatalf("counts changed across identical calls: %+v vs %+v", c1, c2)
	}
	if v1 != v2 {
		t.Fatalf("maxVersion changed across identical calls: %d vs %d", v1, v2)
	}
	// 10K placements × 2 ports + 1 sandbox-level route = 30K hash entries.
	// counts.http = sandbox-level routes (10K) + per-port HTTP (10K) = 20K.
	// counts.tcp = per-port TCP (10K).
	if c1.http != 20_000 || c1.tcp != 10_000 || c1.tls != 0 {
		t.Fatalf("counts mismatch: http=%d tls=%d tcp=%d", c1.http, c1.tls, c1.tcp)
	}
	if v1 != 10_000 {
		t.Fatalf("maxVersion = %d, want 10000", v1)
	}
	t.Logf("hashPlacementView(10K): first=%s, repeat=%s", first, second)
}

// TestHashPlacementViewAt10KDetectsSingleMutation pins that one placement
// flipping its Version is observable in the hash even when buried in 10K
// peers. Without this, the reconciler would silently miss small drifts —
// an ExposePort on one sandbox would never trigger a route reinstall if
// 9,999 unchanged peers diluted the hash.
func TestHashPlacementViewAt10KDetectsSingleMutation(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test skipped under -short")
	}
	placements := makeScalePlacements(10_000)
	before, _, _ := hashPlacementView("ingress-self", placements)

	// Bump the version on a single placement in the middle of the set.
	placements[5_000].Version = 99_999_999
	after, _, _ := hashPlacementView("ingress-self", placements)

	if before == after {
		t.Fatalf("hash did not change when one of 10K placements bumped Version")
	}
}

// TestRunIngressOpsAt10KCompletesAll is the worker-pool scale claim: with
// 10K fast ops and concurrency=8, every op must run, the pool must not
// deadlock, and observed in-flight concurrency must respect the cap. The
// reconciler's correctness depends on "every queued admin call eventually
// runs" — a leak here would silently drop routes.
func TestRunIngressOpsAt10KCompletesAll(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test skipped under -short")
	}
	const n = 10_000
	var ran, inFlight, peakInFlight atomic.Int64
	ops := make([]func(context.Context) error, n)
	for i := 0; i < n; i++ {
		ops[i] = func(_ context.Context) error {
			cur := inFlight.Add(1)
			// Track high-water mark with a compare-and-swap retry so the
			// observed peak never undercounts under contention.
			for {
				prev := peakInFlight.Load()
				if cur <= prev || peakInFlight.CompareAndSwap(prev, cur) {
					break
				}
			}
			ran.Add(1)
			inFlight.Add(-1)
			return nil
		}
	}

	start := time.Now()
	if err := runIngressOps(context.Background(), ops, clusterIngressMaxConcurrentWrites); err != nil {
		t.Fatalf("runIngressOps: %v", err)
	}
	elapsed := time.Since(start)

	if got := ran.Load(); got != n {
		t.Fatalf("ran=%d, want %d (ops were dropped by the pool)", got, n)
	}
	if peak := peakInFlight.Load(); peak > clusterIngressMaxConcurrentWrites {
		t.Fatalf("peak concurrency = %d, exceeded cap %d", peak, clusterIngressMaxConcurrentWrites)
	}
	t.Logf("runIngressOps(10K, cc=%d): wall=%s, peak in-flight=%d",
		clusterIngressMaxConcurrentWrites, elapsed, peakInFlight.Load())
}

// BenchmarkHashPlacementView10K gives operators a number to track over time.
// At the 10K mark this is the inner-loop cost the idle-skip is paying every
// tick; a regression that pushes this from ~ms to ~100ms would silently
// starve the reconciler.
func BenchmarkHashPlacementView10K(b *testing.B) {
	placements := makeScalePlacements(10_000)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, _ = hashPlacementView("ingress-self", placements)
	}
}
