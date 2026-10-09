package service

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/pkg/models"
)

func syncedIDs(gw *fakeGateway) map[string]bool {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	out := map[string]bool{}
	if len(gw.synced) == 0 {
		return out
	}
	for _, s := range gw.synced[len(gw.synced)-1] {
		out[s.ID] = true
	}
	return out
}

// TestFullSyncKeepsAnInflightAttach (review finding 1): a create's attach
// runs alongside its row persist, so a full Sync built from the store alone
// would detach a sandbox whose Attach just succeeded (and whose driver block
// was lifted). The Sync includes it until its row is written.
func TestFullSyncKeepsAnInflightAttach(t *testing.T) {
	svc, gw, rt := newEgressHarness(t)
	ctx := context.Background()
	if err := svc.EnsureEgressGatewayReady(ctx); err != nil {
		t.Fatal(err)
	}
	sb := &models.Sandbox{ID: "sb-new", ContainerIP: "10.0.0.9", Status: models.SandboxStatusStarted, NetworkAllowOut: []string{"pypi.org"}}
	if err := svc.attachSandboxEgress(ctx, sb, rt); err != nil {
		t.Fatal(err)
	}
	if err := svc.ResyncEgressGateway(ctx); err != nil {
		t.Fatal(err)
	}
	if !syncedIDs(gw)["sb-new"] || !gw.isAttached("sb-new") {
		t.Fatal("a full Sync must keep an attach whose row isn't written yet")
	}
	// Settled with no row (the create rolled back without a detach): gone.
	svc.settleEgressAttach("sb-new")
	if err := svc.ResyncEgressGateway(ctx); err != nil {
		t.Fatal(err)
	}
	if syncedIDs(gw)["sb-new"] {
		t.Fatal("a settled attach is the store's to describe")
	}
	// A detach drops it as well.
	if err := svc.attachSandboxEgress(ctx, sb, rt); err != nil {
		t.Fatal(err)
	}
	svc.detachSandboxEgress(ctx, sb, sb.ContainerIP)
	if svc.egressInflight.len() != 0 {
		t.Fatal("detach must drop the in-flight entry")
	}
}

func TestInflightMerge(t *testing.T) {
	var f egressInflight
	now := time.Now()
	a := egress.Spec{ID: "a", IP: netip.MustParseAddr("10.0.0.1")}
	b := egress.Spec{ID: "b", IP: netip.MustParseAddr("10.0.0.2")}
	c := egress.Spec{ID: "c", IP: netip.MustParseAddr("10.0.0.3")}
	f.put(a)
	f.put(b)
	f.put(c)
	f.m["c"] = inflightSpec{spec: c, at: now.Add(-egressInflightMaxAge - time.Minute)}
	// a: its row now shows it started on the same IP (store wins, entry
	// dropped). b: no row yet (kept). c: too old (dropped).
	got := f.merge([]egress.Spec{a}, map[string]netip.Addr{"a": a.IP}, now)
	if len(got) != 2 || got[1].ID != "b" {
		t.Fatalf("merged = %+v", got)
	}
	if f.len() != 1 {
		t.Fatalf("left %d entries, want only b", f.len())
	}
	// A row on another IP doesn't cover the entry.
	if got := f.merge(nil, map[string]netip.Addr{"b": netip.MustParseAddr("10.9.9.9")}, now); len(got) != 1 {
		t.Fatalf("a row on another IP must not cover the attach: %+v", got)
	}
}

// TestLayoutLossRecoveryIsSingleFlight (review finding 12): a recovery in
// progress isn't started again by the next heartbeat, and the held gauge is
// recounted once per recovery, not once per sandbox.
func TestLayoutLossRecoveryIsSingleFlight(t *testing.T) {
	svc, _, _ := newEgressHarness(t)
	ctx := context.Background()
	svc.egressRecovering.Store(true)
	svc.onEgressLayoutLost(ctx)
	if svc.egressStats.layoutLost.Load() != 0 {
		t.Fatal("a second recovery must not start while one runs")
	}
	svc.egressRecovering.Store(false)

	svc.egressGaugeBatch.Add(1)
	svc.egressStats.held.Store(42)
	svc.refreshHeldGauge(ctx)
	if svc.egressStats.held.Load() != 42 || !svc.egressGaugeDirty.Load() {
		t.Fatal("inside a batch the recount must be deferred")
	}
	svc.endGaugeBatch(ctx)
	if svc.egressStats.held.Load() != 0 || svc.egressGaugeDirty.Load() {
		t.Fatal("the batch's end must recount once")
	}
}

// TestFullSyncSendsTheRecordingInventory (review finding 13): every full
// Sync is followed by the inventory of the sandboxes this node still holds,
// stopped ones and attaches not yet written included, so the gateway can
// collect recordings whose forget never arrived.
func TestFullSyncSendsTheRecordingInventory(t *testing.T) {
	svc, gw, rt := newEgressHarness(t)
	ctx := context.Background()
	stopped := &models.Sandbox{ID: "sb-stopped", Image: "alpine", Status: models.SandboxStatusStopped, CreatedAt: time.Now(), UpdatedAt: time.Now(), LastActiveAt: time.Now()}
	if err := svc.store.Create(ctx, stopped); err != nil {
		t.Fatal(err)
	}
	if err := svc.EnsureEgressGatewayReady(ctx); err != nil {
		t.Fatal(err)
	}
	inflight := &models.Sandbox{ID: "sb-creating", ContainerIP: "10.0.0.7", Status: models.SandboxStatusStarted, NetworkAllowOut: []string{"pypi.org"}}
	if err := svc.attachSandboxEgress(ctx, inflight, rt); err != nil {
		t.Fatal(err)
	}
	if err := svc.ResyncEgressGateway(ctx); err != nil {
		t.Fatal(err)
	}
	gw.mu.Lock()
	retained, n := append([]string(nil), gw.retained...), gw.retains
	gw.mu.Unlock()
	if n < 2 || !slices.Contains(retained, "sb-stopped") || !slices.Contains(retained, "sb-creating") {
		t.Fatalf("inventory = %v after %d sends", retained, n)
	}
	if svc.egressRetainedAt.Load() == 0 {
		t.Fatal("a successful send is recorded for the hourly pacing")
	}
}
