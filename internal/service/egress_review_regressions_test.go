package service

// Regression tests from the second review of PR #622: each reproduces a
// finding against the reviewed head and passes with its fix.

import (
	"context"
	"errors"
	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/pkg/models"
	"net/netip"
	"testing"
	"time"
)

func TestReconcileKeepsAnUnresolvedProfileHold(t *testing.T) {
	svc, _, _ := newPolicyHarness(t)
	ctx := context.Background()
	sb := seedPolicySandbox(t, svc, models.Sandbox{})
	putProfile(t, svc, ctx, "web", "pypi.org")
	if _, err := svc.UpdateNetworkPolicy(ctx, sb.ID, models.NetworkPolicyRequest{EgressProfiles: []string{"web"}}); err != nil {
		t.Fatal(err)
	}
	svc.egressProfiles = noClusterProfiles{}
	svc.reapplyEgressProfiles(ctx)
	st, _ := svc.store.GetEgressState(ctx, sb.ID)
	if st.HoldReason != egressHoldProfileUnavailable {
		t.Fatalf("setup: hold=%q", st.HoldReason)
	}
	row, err := svc.store.Get(ctx, sb.ID)
	if err != nil {
		t.Fatal(err)
	}
	svc.reconcileSandboxEgress(ctx, row)
	st, _ = svc.store.GetEgressState(ctx, sb.ID)
	if st.HoldReason == "" {
		t.Fatal("ordinary reconciliation released a profile hold by attaching stale cached permissions while the profile is still unavailable")
	}
}

func TestMediatedRetryDoesNotNeedTheGateway(t *testing.T) {
	svc, _, _ := newPolicyHarness(t)
	svc.cfg.EgressFQDNEnabled = false
	m := newMediator()
	svc.wasm = m
	sb := seedPolicySandbox(t, svc, models.Sandbox{ID: "local-wasm", Runtime: models.RuntimeWasm, NetworkAllowOut: []string{"pypi.org"}})
	m.err = errors.New("temporary worker failure")
	req := models.NetworkPolicyRequest{NetworkAllowOut: []string{"github.com"}}
	if _, err := svc.UpdateNetworkPolicy(context.Background(), sb.ID, req); !errors.Is(err, ErrEgressApplyFailedHeld) {
		t.Fatalf("setup: %v", err)
	}
	m.err = nil
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	svc.SuperviseEgressGateway(ctx, time.Millisecond)
	// The supervisor retries apply_failed on every worker, including one
	// with the gateway disabled.
	st, err := svc.store.GetEgressState(context.Background(), sb.ID)
	if err != nil {
		t.Fatal(err)
	}
	if st.HoldReason != "" {
		t.Fatal("mediated apply failure is never retried by the production supervisor when the unrelated gateway is disabled")
	}
}

type pausingSyncGateway struct {
	*fakeGateway
	real            *egress.Gateway
	entered, resume chan struct{}
}

func (g *pausingSyncGateway) Attach(_ context.Context, s egress.Spec) error { return g.real.Attach(s) }
func (g *pausingSyncGateway) SetBlocked(_ context.Context, id string, r egress.BlockReason, on bool) error {
	return g.real.SetBlocked(id, r, on)
}
func (g *pausingSyncGateway) SyncToken(context.Context) (egress.SyncToken, error) {
	return g.real.SyncToken(), nil
}
func (g *pausingSyncGateway) Sync(_ context.Context, specs []egress.Spec, tok egress.SyncToken) error {
	if g.entered != nil {
		close(g.entered)
		<-g.resume
	}
	return g.real.SyncFrom(tok, specs)
}
func TestFullSyncKeepsAConcurrentHold(t *testing.T) {
	svc, fake, rt := newPolicyHarness(t)
	real := egress.New(egress.Options{Backend: egress.NewMemBackend()})
	if err := real.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	gw := &pausingSyncGateway{fakeGateway: fake, real: real}
	svc.SetEgressGateway(gw, func(context.Context) []egress.Bridge {
		return []egress.Bridge{{Name: "docker0", GatewayIP: netip.MustParseAddr("172.17.0.1")}}
	})
	ctx := context.Background()
	sb := seedPolicySandbox(t, svc, models.Sandbox{NetworkAllowOut: []string{"pypi.org"}})
	if err := svc.attachSandboxEgress(ctx, sb, rt); err != nil {
		t.Fatal(err)
	}
	gw.entered, gw.resume = make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- svc.ResyncEgressGateway(ctx) }()
	<-gw.entered
	svc.holdUnapplied(ctx, sb, egressHoldProfileUnavailable)
	if !real.IsBlocked(sb.ID) {
		close(gw.resume)
		<-done
		t.Fatal("setup: hold not applied")
	}
	close(gw.resume)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	st, _ := svc.store.GetEgressState(ctx, sb.ID)
	if st.HoldReason != "" && !real.IsBlocked(sb.ID) {
		t.Fatal("full Sync erased a concurrent durable profile hold from the real gateway")
	}
}

func TestDestroyReleasesThePidCache(t *testing.T) {
	svc, _, rt := newPolicyHarness(t)
	rt.pid = 4242
	sb := seedPolicySandbox(t, svc, models.Sandbox{AuditIncarnationID: "review-inc", NetworkAllowOut: []string{"pypi.org"}, NetworkEgressRules: []models.EgressRule{{Host: "pypi.org", Ports: []uint16{443}, Binaries: []string{"/usr/bin/curl"}}}})
	if svc.egressPid(context.Background(), sb) != 4242 {
		t.Fatal("setup: no pid")
	}
	if err := svc.DestroySandbox(context.Background(), sb.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := svc.egressPids.Load(sb.ID); ok {
		t.Fatal("successful destroy retains the sandbox id, container id and PID in the new cache")
	}
}

func TestQuotaSyncKeepsAWasmHold(t *testing.T) {
	svc, _, _ := newPolicyHarness(t)
	m := newMediator()
	svc.wasm = m
	sb := seedPolicySandbox(t, svc, models.Sandbox{ID: "held-wasm", Runtime: models.RuntimeWasm, NetworkAllowOut: []string{"pypi.org"}})
	ctx := context.Background()
	svc.holdUnapplied(ctx, sb, egressHoldProfileUnavailable)
	if !m.blocked[sb.ID] {
		t.Fatal("setup: hold not applied")
	}
	svc.applyNetworkQuotaState(ctx, sb, false, false)
	st, err := svc.store.GetEgressState(ctx, sb.ID)
	if err != nil {
		t.Fatal(err)
	}
	if st.HoldReason != "" && !m.blocked[sb.ID] {
		t.Fatal("quota reconciliation reopened WASM while its profile hold is still persisted")
	}
}

func TestCrossModeRetryDetachesTheOldGateway(t *testing.T) {
	svc, gw, rt := newPolicyHarness(t)
	ctx := context.Background()
	sb := seedPolicySandbox(t, svc, models.Sandbox{NetworkAllowOut: []string{"pypi.org"}})
	if err := svc.attachSandboxEgress(ctx, sb, rt); err != nil {
		t.Fatal(err)
	}
	rt.blockErr = errors.New("temporary iptables failure")
	req := models.NetworkPolicyRequest{NetworkAllowOut: []string{"8.8.8.0/24"}}
	if _, err := svc.UpdateNetworkPolicy(ctx, sb.ID, req); !errors.Is(err, ErrEgressApplyFailedHeld) {
		t.Fatalf("setup: %v", err)
	}
	rt.blockErr = nil
	if _, err := svc.UpdateNetworkPolicy(ctx, sb.ID, req); err != nil {
		t.Fatal(err)
	}
	if gw.isAttached(sb.ID) {
		t.Fatal("successful gateway-to-CIDR retry leaves the old hostname gateway policy attached")
	}
}

// TestHoldRanksAndReleases: a weaker hold never overwrites a stronger one,
// and a gateway reattach (here the table-loss recovery) lifts only gateway
// holds, so an unresolved profile stays shut.
func TestHoldRanksAndReleases(t *testing.T) {
	ctx := context.Background()
	svc, gw, rt := newPolicyHarness(t)
	sb := seedPolicySandbox(t, svc, models.Sandbox{NetworkAllowOut: []string{"pypi.org"}})
	if err := svc.attachSandboxEgress(ctx, sb, rt); err != nil {
		t.Fatal(err)
	}
	svc.holdSandboxEgress(ctx, sb, rt, egressHoldProfileUnavailable)
	svc.holdSandboxEgress(ctx, sb, rt, egressHoldLayoutLost)
	if st, _ := svc.store.GetEgressState(ctx, sb.ID); st.HoldReason != egressHoldProfileUnavailable {
		t.Fatalf("a gateway hold overwrote a profile hold: %q", st.HoldReason)
	}
	svc.handleEgressEvent(ctx, egress.Event{Kind: "heartbeat", LayoutLostSeen: true})
	if st, _ := svc.store.GetEgressState(ctx, sb.ID); st.HoldReason != egressHoldProfileUnavailable {
		t.Fatalf("the reattach must not lift a profile hold: %q", st.HoldReason)
	}
	gw.mu.Lock()
	blocked := gw.blocked[sb.ID]&egress.BlockHold != 0
	gw.mu.Unlock()
	if !blocked {
		t.Fatal("the gateway must keep the hold block")
	}
	// A stronger reason replaces a weaker one.
	sb2 := seedPolicySandbox(t, svc, models.Sandbox{ID: "sb-2", NetworkAllowOut: []string{"pypi.org"}})
	svc.holdSandboxEgress(ctx, sb2, rt, egressHoldAttachFailed)
	svc.holdSandboxEgress(ctx, sb2, rt, egressHoldApplyFailed)
	if st, _ := svc.store.GetEgressState(ctx, sb2.ID); st.HoldReason != egressHoldApplyFailed {
		t.Fatalf("a stronger hold must replace a weaker one: %q", st.HoldReason)
	}
}

// TestIsolatePolicyPushKeepsTheHold: an isolate policy push composes
// block-all from a recorded hold, so it can't reopen a held sandbox; the
// release that resolves the hold re-syncs it open.
func TestIsolatePolicyPushKeepsTheHold(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newPolicyHarness(t)
	iso := newMediator()
	svc.isolate = iso
	sb := seedPolicySandbox(t, svc, models.Sandbox{ID: "sb-iso", Runtime: models.RuntimeIsolate, NetworkAllowOut: []string{"pypi.org"}})
	svc.holdUnapplied(ctx, sb, egressHoldProfileUnavailable)
	if err := svc.applyIsolatePolicy(ctx, sb); err != nil || !iso.blocked[sb.ID] {
		t.Fatalf("a push while held must keep block-all: %v %v", err, iso.blocked)
	}
	if err := svc.releaseHold(ctx, sb, applyHolds...); err != nil || !iso.blocked[sb.ID] {
		t.Fatal("an apply retry can't lift a profile hold")
	}
	if err := svc.releaseHold(ctx, sb, allHolds...); err != nil || iso.blocked[sb.ID] {
		t.Fatalf("the resolving release re-syncs it open: %v %v", err, iso.blocked)
	}
}

// TestMediatedHoldShutsWithoutTheStore: a hold whose record can't be written
// still shuts the WASM and isolate mediators, since the composed block
// state can't read a hold the store never took.
func TestMediatedHoldShutsWithoutTheStore(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newPolicyHarness(t)
	wasm, iso := newMediator(), newMediator()
	svc.wasm, svc.isolate = wasm, iso
	w := seedPolicySandbox(t, svc, models.Sandbox{ID: "sb-wasm", Runtime: models.RuntimeWasm, NetworkAllowOut: []string{"pypi.org"}})
	i := seedPolicySandbox(t, svc, models.Sandbox{ID: "sb-iso", Runtime: models.RuntimeIsolate, NetworkAllowOut: []string{"pypi.org"}})
	_ = svc.store.Close()
	svc.holdUnapplied(ctx, w, egressHoldApplyFailed)
	svc.holdUnapplied(ctx, i, egressHoldApplyFailed)
	if !wasm.blocked[w.ID] || !iso.blocked[i.ID] {
		t.Fatalf("a hold the store refused must still shut the mediators: wasm=%v iso=%v", wasm.blocked, iso.blocked)
	}
}
