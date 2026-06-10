package service

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestHashPlacementViewStable asserts the hash is order-independent and only
// shifts when the inputs the reconciler actually consumes change. This is the
// load-bearing claim behind the idle-skip path: at steady state we must NOT
// flap the hash between ticks, otherwise we'd keep hammering Caddy admin.
func TestHashPlacementViewStable(t *testing.T) {
	a := cluster.Placement{
		SandboxID:          "sb-1",
		OwnerNodeID:        "node-a",
		OwnerAPIURL:        "http://a:21212",
		OwnerDataPlaneHost: "a.lan",
		Version:            5,
	}
	b := cluster.Placement{
		SandboxID:          "sb-2",
		OwnerNodeID:        "node-b",
		OwnerAPIURL:        "http://b:21212",
		OwnerDataPlaneHost: "b.lan",
		Version:            7,
		ExposedPortRoutes: map[int]cluster.ExposedPortRoute{
			3000: {Protocol: models.ExposedPortProtocolHTTP},
			5432: {Protocol: models.ExposedPortProtocolTCP, HostPort: 22432},
		},
	}

	h1, _, _ := hashPlacementView("self", []cluster.Placement{a, b})
	h2, _, _ := hashPlacementView("self", []cluster.Placement{b, a}) // reversed
	if h1 != h2 {
		t.Fatalf("hash is order-dependent: %x vs %x", h1, h2)
	}
}

// TestHashPlacementViewChangesOnVersion confirms a placement.Version bump is
// observable through the hash — that's how the reconciler notices an
// ExposePort or owner change.
func TestHashPlacementViewChangesOnVersion(t *testing.T) {
	a := cluster.Placement{
		SandboxID:   "sb-1",
		OwnerNodeID: "node-a",
		Version:     5,
	}
	h1, _, _ := hashPlacementView("self", []cluster.Placement{a})
	a.Version = 6
	h2, _, _ := hashPlacementView("self", []cluster.Placement{a})
	if h1 == h2 {
		t.Fatalf("hash did not change after Version bump")
	}
}

// TestHashPlacementViewIgnoresSelfOwned confirms placements that the
// reconciler would skip (owner==self) don't move the hash — otherwise an
// ingress node owning sandboxes locally would defeat its own idle-skip
// every time the local sandbox set churned.
func TestHashPlacementViewIgnoresSelfOwned(t *testing.T) {
	mine := cluster.Placement{SandboxID: "sb-mine", OwnerNodeID: "self", Version: 1}
	theirs := cluster.Placement{SandboxID: "sb-theirs", OwnerNodeID: "other", Version: 1}
	h1, _, _ := hashPlacementView("self", []cluster.Placement{theirs})
	h2, _, _ := hashPlacementView("self", []cluster.Placement{mine, theirs})
	if h1 != h2 {
		t.Fatalf("self-owned placement leaked into hash: %x vs %x", h1, h2)
	}
}

// TestRunIngressOpsRunsAllInParallel exercises the worker pool used by the
// per-tick Caddy admin fan-out. With concurrency=4 and 8 ops that each sleep
// 50ms, the wall-clock should be ~100ms (two batches), not ~400ms (serial).
// This is the load-bearing claim behind dropping 10K-route reconcile time
// from ~10s to ~1.5s under realistic admin latency.
func TestRunIngressOpsRunsAllInParallel(t *testing.T) {
	const n = 8
	var ran atomic.Int32
	ops := make([]func(context.Context) error, n)
	for i := 0; i < n; i++ {
		ops[i] = func(_ context.Context) error {
			time.Sleep(50 * time.Millisecond)
			ran.Add(1)
			return nil
		}
	}
	start := time.Now()
	if err := runIngressOps(context.Background(), ops, 4); err != nil {
		t.Fatalf("runIngressOps: %v", err)
	}
	elapsed := time.Since(start)
	if got := ran.Load(); got != n {
		t.Fatalf("ran=%d, want %d", got, n)
	}
	// Conservative bound: serial would be ~400ms; parallel-by-4 should
	// finish well under 250ms even on a busy CI machine.
	if elapsed > 250*time.Millisecond {
		t.Fatalf("ops took %s; expected concurrency to bring it well under 250ms", elapsed)
	}
}

// TestRunIngressOpsReturnsFirstError surfaces the first error from any op
// while letting subsequent ops short-circuit. The reconciler uses the
// returned error to invalidate the idle-skip hash so the next tick retries
// the failed admin call.
func TestRunIngressOpsReturnsFirstError(t *testing.T) {
	want := errors.New("admin api 500")
	ops := []func(context.Context) error{
		func(_ context.Context) error { return nil },
		func(_ context.Context) error { return want },
		func(_ context.Context) error { return nil },
	}
	got := runIngressOps(context.Background(), ops, 2)
	if !errors.Is(got, want) {
		t.Fatalf("runIngressOps err = %v, want %v", got, want)
	}
}

// TestHashPlacementViewCounts checks the per-protocol counters that feed
// the route-count expvars.
func TestHashPlacementViewCounts(t *testing.T) {
	p := cluster.Placement{
		SandboxID:   "sb",
		OwnerNodeID: "remote",
		Version:     1,
		ExposedPortRoutes: map[int]cluster.ExposedPortRoute{
			3000: {Protocol: models.ExposedPortProtocolHTTP},
			8443: {Protocol: models.ExposedPortProtocolTLS},
			5432: {Protocol: models.ExposedPortProtocolTCP, HostPort: 22432},
		},
	}
	_, counts, maxVersion := hashPlacementView("self", []cluster.Placement{p})
	// The sandbox itself contributes one HTTP-or-TLS entry to counts.http
	// (the reconciler picks the protocol at apply time).
	if counts.http != 2 || counts.tls != 1 || counts.tcp != 1 {
		t.Fatalf("counts mismatch: http=%d tls=%d tcp=%d", counts.http, counts.tls, counts.tcp)
	}
	shard := cluster.PlacementShardForSandbox("sb", cluster.DefaultPlacementShardCount)
	if got := counts.shards[shard]; got != 4 {
		t.Fatalf("shard route count = %d, want 4", got)
	}
	if maxVersion != 1 {
		t.Fatalf("maxVersion = %d, want 1", maxVersion)
	}
}

func TestRecordIngressReconcilePublishesRevisionAndShardMetrics(t *testing.T) {
	shard := cluster.PlacementShardForSandbox("sb-metrics", cluster.DefaultPlacementShardCount)
	counts := ingressRouteCounts{http: 1, shards: map[int]int{shard: 1}}
	recordIngressReconcile(reconcileApplied, time.Millisecond, counts, 55)
	if got := ingressRouteAppliedRevision.Value(); got < 55 {
		t.Fatalf("applied revision = %d, want at least 55", got)
	}
	if got := ingressRoutesByShard.Get(strconv.Itoa(shard)); got == nil || got.String() != "1" {
		t.Fatalf("routes by shard = %v, want 1", got)
	}

	recordIngressReconcile(reconcileErrored, time.Millisecond, counts, 56)
	if got := ingressRouteFailedRevision.Value(); got != 56 {
		t.Fatalf("failed revision = %d, want 56", got)
	}
}

func TestIngressMetricsHelperBranches(t *testing.T) {
	beforeMisses := ingressRouteMissesTotal.Value()
	RecordRouteMiss()
	RecordRouteMiss("custom_reason")
	if got := ingressRouteMissesTotal.Value(); got < beforeMisses+2 {
		t.Fatalf("route miss total = %d, want at least %d", got, beforeMisses+2)
	}
	if got := ingressRouteMissesByReason.String(); !strings.Contains(got, "custom_reason") {
		t.Fatalf("route misses by reason = %s, want custom_reason", got)
	}

	ops := []func(context.Context) error{
		func(context.Context) error { return nil },
		func(context.Context) error { return errors.New("boom") },
	}
	if err := runIngressOpsBatched(context.Background(), ops, 1, 1); err == nil {
		t.Fatal("runIngressOpsBatched should surface the first error")
	}

	prev := ingressPlacementVersionMax.Value()
	defer ingressPlacementVersionMax.Set(prev)
	ingressPlacementVersionMax.Set(10)
	SetIngressRouteLag(8)
	if got := ingressRouteLagVersions.Value(); got != 0 {
		t.Fatalf("route lag = %d, want 0 when FSM is behind installed version", got)
	}
	SetIngressRouteLag(12)
	if got := ingressRouteLagVersions.Value(); got != 2 {
		t.Fatalf("route lag = %d, want 2", got)
	}
	if got := IngressInstalledVersion(); got != 10 {
		t.Fatalf("IngressInstalledVersion = %d, want 10", got)
	}
	ingressPlacementVersionMax.Set(-1)
	if got := IngressInstalledVersion(); got != 0 {
		t.Fatalf("IngressInstalledVersion = %d, want 0 for negative state", got)
	}
}
