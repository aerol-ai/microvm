package service

// Regression tests from the fourth review of PR #622: each reproduces a
// finding against the reviewed head (4fdb667c) and passes with its fix.

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestFirstRemovalKeepsTheInstalledGateway(t *testing.T) {
	svc, fake, rt := newPolicyHarness(t)
	gw := &flakyBlocksGateway{fakeGateway: fake, detachErr: errors.New("detach unavailable")}
	svc.SetEgressGateway(gw, nil)
	ctx := context.Background()
	sb := seedPolicySandbox(t, svc, models.Sandbox{NetworkAllowOut: []string{"pypi.org"}})
	if err := svc.attachSandboxEgress(ctx, sb, rt); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpdateNetworkPolicy(ctx, sb.ID, models.NetworkPolicyRequest{NetworkBlockAll: true}); !errors.Is(err, ErrEgressApplyFailedHeld) {
		t.Fatalf("setup: %v", err)
	}
	st, err := svc.store.GetEgressState(ctx, sb.ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("after failed first removal: installed=%+v hold=%q", st.Installed, st.HoldReason)
	gw.detachErr = nil
	if err := svc.reapplyStoredPolicy(ctx, sb.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpdateNetworkPolicy(ctx, sb.ID, models.NetworkPolicyRequest{NetworkAllowOut: []string{"1.1.1.0/24"}}); err != nil {
		t.Fatal(err)
	}
	st, err = svc.store.GetEgressState(ctx, sb.ID)
	if err != nil {
		t.Fatal(err)
	}
	if fake.isAttached(sb.ID) && st.HoldReason == "" {
		t.Fatal("failed removal, retry, and later CIDR-only PUT all settled with the old hostname gateway still attached and unheld")
	}
}

type quotaHookRuntime struct {
	*policyRuntime
	onBlock func()
}

func (r *quotaHookRuntime) ApplyNetworkBlockAll(ip string) error {
	r.onBlock()
	return r.policyRuntime.ApplyNetworkBlockAll(ip)
}

func TestFullSyncKeepsAQuotaBlockWrittenBeforeItsFlag(t *testing.T) {
	svc, fake, rt := newPolicyHarness(t)
	real := egress.New(egress.Options{Backend: egress.NewMemBackend()})
	if err := real.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	gw := &newerHoldSyncGateway{fakeGateway: fake, real: real}
	svc.SetEgressGateway(gw, nil)
	ctx := context.Background()
	sb := seedPolicySandbox(t, svc, models.Sandbox{NetworkAllowOut: []string{"pypi.org"}, NetworkBytesOutLimit: 100, NetworkBytesOut: 200})
	if err := svc.attachSandboxEgress(ctx, sb, rt); err != nil {
		t.Fatal(err)
	}
	// Force a legal concurrent Sync at the runtime boundary: the real
	// quota path has acknowledged SetBlocked but not yet stored its flag.
	svc.docker = &quotaHookRuntime{policyRuntime: rt, onBlock: func() {
		if !real.IsBlocked(sb.ID) {
			t.Fatal("setup: quota was not installed")
		}
		if err := svc.ResyncEgressGateway(ctx); err != nil {
			t.Fatal(err)
		}
	}}
	svc.applyNetworkQuotaState(ctx, sb, false, true)
	stored, err := svc.store.Get(ctx, sb.ID)
	if err != nil || !stored.NetworkQuotaExceeded {
		t.Fatalf("quota flag: %+v, %v", stored, err)
	}
	if !real.IsBlocked(sb.ID) {
		t.Fatal("quota path completed with database quota flag set but its acknowledged gateway block removed by Sync")
	}
}

type detachRetryGateway struct {
	*newerHoldSyncGateway
	detachErr error
}

func (g *detachRetryGateway) Detach(_ context.Context, id string, ip netip.Addr) error {
	if g.detachErr != nil {
		return g.detachErr
	}
	return g.real.Detach(id, ip)
}

func (g *detachRetryGateway) RetainLearned(ctx context.Context, ids []string) error {
	g.real.RetainBlocks(ids)
	return g.fakeGateway.RetainLearned(ctx, ids)
}

func TestDestroyDetachFailureIsRetried(t *testing.T) {
	svc, fake, rt := newPolicyHarness(t)
	real := egress.New(egress.Options{Backend: egress.NewMemBackend()})
	if err := real.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	gw := &detachRetryGateway{newerHoldSyncGateway: &newerHoldSyncGateway{fakeGateway: fake, real: real}, detachErr: errors.New("temporary detach transaction failure")}
	svc.SetEgressGateway(gw, nil)
	ctx := context.Background()
	sb := seedPolicySandbox(t, svc, models.Sandbox{NetworkAllowOut: []string{"pypi.org"}, AuditIncarnationID: "review4-gc"})
	if err := svc.attachSandboxEgress(ctx, sb, rt); err != nil {
		t.Fatal(err)
	}
	if err := svc.DestroySandbox(ctx, sb.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.store.Get(ctx, sb.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("sandbox was not destroyed: %v", err)
	}
	gw.detachErr = nil
	// The gateway and event stream stayed healthy; a transient detach
	// failure should still be collected by the normal supervisor.
	svc.egressRetainedAt.Store(0)
	loop, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	svc.SuperviseEgressGateway(loop, time.Millisecond)
	fake.mu.Lock()
	retains := fake.retains
	fake.mu.Unlock()
	if len(real.Specs()) != 0 {
		t.Fatalf("destroyed sandbox remains attached after recovery and retention; specs=%v retains=%d", real.Specs(), retains)
	}
}

// TestDestroyDetachesALeftoverGatewayAttachment: a transition that didn't
// finish can leave a gateway attachment under a non-gateway policy; the
// installed record says so, and destroy detaches it.
func TestDestroyDetachesALeftoverGatewayAttachment(t *testing.T) {
	ctx := context.Background()
	svc, fake, rt := newPolicyHarness(t)
	sb := seedPolicySandbox(t, svc, models.Sandbox{NetworkAllowOut: []string{"pypi.org"}, AuditIncarnationID: "leftover-gw"})
	if err := svc.attachSandboxEgress(ctx, sb, rt); err != nil {
		t.Fatal(err)
	}
	// The stored policy moved to CIDR; the gateway entry wasn't removed.
	if err := svc.store.WriteNetworkPolicy(ctx, sb.ID, store.NetworkPolicyWrite{AllowOut: []string{"8.8.8.0/24"}}); err != nil {
		t.Fatal(err)
	}
	if err := svc.store.SetInstalledEgress(ctx, sb.ID, store.InstalledEgress{Gateway: true, CIDR: []store.CIDRRules{{Allow: []string{"8.8.8.0/24"}}}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := svc.DestroySandbox(ctx, sb.ID); err != nil {
		t.Fatal(err)
	}
	if fake.isAttached(sb.ID) {
		t.Fatal("destroy must detach a gateway attachment the installed record names")
	}
}

// TestTerminalDetachRetry: a failed terminal detach is retried until it
// lands; a sandbox attached again under the same id (started) owns its
// entry, and the intent is dropped without a detach.
func TestTerminalDetachRetry(t *testing.T) {
	ctx := context.Background()
	svc, fake, _ := newPolicyHarness(t)
	gw := &flakyBlocksGateway{fakeGateway: fake, detachErr: fmt.Errorf("%w: detach failed", egress.ErrUnavailable)}
	svc.SetEgressGateway(gw, nil)
	ip := netip.MustParseAddr(policyIP)
	svc.egressDetachPending.add("gone", ip)
	svc.retryTerminalDetaches(ctx)
	if _, ok := svc.egressDetachPending.snapshot()["gone"]; !ok {
		t.Fatal("a detach that still fails stays pending")
	}
	gw.detachErr = nil
	svc.retryTerminalDetaches(ctx)
	fake.mu.Lock()
	detached := slices.Contains(fake.detached, "gone")
	fake.mu.Unlock()
	if !detached || len(svc.egressDetachPending.snapshot()) != 0 {
		t.Fatalf("the retry must detach a destroyed sandbox: detached=%v pending=%v", detached, svc.egressDetachPending.snapshot())
	}
	live := seedPolicySandbox(t, svc, models.Sandbox{ID: "live", NetworkAllowOut: []string{"pypi.org"}})
	svc.egressDetachPending.add(live.ID, ip)
	svc.retryTerminalDetaches(ctx)
	fake.mu.Lock()
	detachedLive := slices.Contains(fake.detached, live.ID)
	fake.mu.Unlock()
	if detachedLive || len(svc.egressDetachPending.snapshot()) != 0 {
		t.Fatalf("a started sandbox owns its entry: detached=%v pending=%v", detachedLive, svc.egressDetachPending.snapshot())
	}
}
