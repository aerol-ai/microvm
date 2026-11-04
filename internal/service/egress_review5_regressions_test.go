package service

// Regression tests from the fifth review of PR #622: each reproduces a
// finding against the reviewed head (a9b64e06) and passes with its fix.

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestReconcileOfAGoneSandboxDetachesIt(t *testing.T) {
	svc, fake, rt := newPolicyHarness(t)
	real := egress.New(egress.Options{Backend: egress.NewMemBackend()})
	if err := real.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	gw := &detachRetryGateway{newerHoldSyncGateway: &newerHoldSyncGateway{fakeGateway: fake, real: real}}
	svc.SetEgressGateway(gw, nil)
	ctx := context.Background()
	sb := seedPolicySandbox(t, svc, models.Sandbox{NetworkAllowOut: []string{"pypi.org"}, AuditIncarnationID: "review5-gone"})
	if err := svc.attachSandboxEgress(ctx, sb, rt); err != nil {
		t.Fatal(err)
	}
	// Runtime list and targeted inspect both report the container gone;
	// its destroy event was missed, so ordinary reconcile owns cleanup.
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.store.Get(ctx, sb.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("row not reaped: %v", err)
	}
	svc.retryTerminalDetaches(ctx)
	if len(real.Specs()) != 0 {
		t.Fatalf("Reconcile deleted the row but left its gateway attachment and no detach intent: specs=%v pending=%v", real.Specs(), svc.egressDetachPending.snapshot())
	}
}

type stopHookRuntime struct {
	*policyRuntime
	onClearHold func()
}

func (r *stopHookRuntime) ClearEgressHold(ip string) error {
	if r.onClearHold != nil {
		r.onClearHold()
	}
	return r.policyRuntime.ClearEgressHold(ip)
}

func TestStopRetryIgnoresTheOldStartedRow(t *testing.T) {
	svc, fake, rt := newPolicyHarness(t)
	gw := &flakyBlocksGateway{fakeGateway: fake, detachErr: errors.New("temporary detach failure")}
	svc.SetEgressGateway(gw, nil)
	ctx := context.Background()
	sb := seedPolicySandbox(t, svc, models.Sandbox{NetworkAllowOut: []string{"pypi.org"}})
	if err := svc.attachSandboxEgress(ctx, sb, rt); err != nil {
		t.Fatal(err)
	}
	// The normal stop-event path queues detach before writing Stopped.
	// Run a supervisor retry in that interval; no new Attach took place.
	svc.docker = &stopHookRuntime{policyRuntime: rt, onClearHold: func() {
		gw.detachErr = nil
		svc.retryTerminalDetaches(ctx)
	}}
	if err := svc.markSandboxStopped(ctx, sb, docker.DockerEvent{Action: "die"}); err != nil {
		t.Fatal(err)
	}
	svc.retryTerminalDetaches(ctx)
	if fake.isAttached(sb.ID) {
		t.Fatalf("stop completed but retry discarded the detach as a reattach; pending=%v", svc.egressDetachPending.snapshot())
	}
}

func TestStopClearsEveryPartOfTheInstalledRecord(t *testing.T) {
	svc, fake, rt := newPolicyHarness(t)
	ctx := context.Background()
	old := []string{"8.8.8.0/24"}
	sb := seedPolicySandbox(t, svc, models.Sandbox{NetworkAllowOut: old})
	if err := rt.ApplyEgressPolicy(sb.ContainerIP, old, nil); err != nil {
		t.Fatal(err)
	}
	// A failed first clear leaves the old CIDR rules; the transition
	// journal also conservatively names its new gateway target.
	rt.clearErr = errors.New("iptables clear failed")
	if _, err := svc.UpdateNetworkPolicy(ctx, sb.ID, models.NetworkPolicyRequest{NetworkAllowOut: []string{"pypi.org"}}); !errors.Is(err, ErrEgressApplyFailedHeld) {
		t.Fatalf("setup: %v", err)
	}
	rt.clearErr = nil
	rt.pmu.Lock()
	rt.cleared = nil
	rt.pmu.Unlock()
	row, err := svc.store.Get(ctx, sb.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.markSandboxStopped(ctx, row, docker.DockerEvent{Action: "die"}); err != nil {
		t.Fatal(err)
	}
	rt.pmu.Lock()
	cleared := slices.Clone(rt.cleared)
	rt.pmu.Unlock()
	if !slices.ContainsFunc(cleared, func(v []string) bool { return slices.Equal(v, old) }) {
		t.Fatalf("stop detached gateway=%v but never cleared installed CIDR rules %v; cleared=%v", !fake.isAttached(sb.ID), old, cleared)
	}
}

func TestCrashAfterTheStoredWriteIsRecovered(t *testing.T) {
	svc, _, rt := newPolicyHarness(t)
	svc.cfg.EgressFQDNEnabled = false
	ctx := context.Background()
	sb := seedPolicySandbox(t, svc, models.Sandbox{NetworkAllowOut: []string{"8.8.8.0/24"}})
	if err := rt.ApplyEgressPolicy(sb.ContainerIP, sb.NetworkAllowOut, nil); err != nil {
		t.Fatal(err)
	}
	next := *sb
	next.NetworkAllowOut = []string{"1.1.1.0/24"}
	st, err := svc.store.GetEgressState(ctx, sb.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.markTransition(ctx, sb, &next, st); err != nil {
		t.Fatal(err)
	}
	if err := svc.store.WriteNetworkPolicy(ctx, sb.ID, store.NetworkPolicyWrite{AllowOut: next.NetworkAllowOut, Inline: next.NetworkAllowOut}); err != nil {
		t.Fatal(err)
	}
	// Crash point: the next production call would be applyStoredTransition,
	// which has not run and therefore has not recorded an apply_failed hold.
	rt.managed = map[string]*models.SandboxRuntimeState{sb.ID: {SandboxID: sb.ID, ContainerID: sb.ContainerID, ContainerIP: sb.ContainerIP, Status: models.SandboxStatusStarted}}
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	svc.egressApplyIdle.Store(false)
	loop, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	svc.SuperviseEgressGateway(loop, time.Millisecond)
	if _, err := svc.UpdateNetworkPolicy(ctx, sb.ID, models.NetworkPolicyRequest{NetworkAllowOut: next.NetworkAllowOut}); err != nil {
		t.Fatal(err)
	}
	rt.pmu.Lock()
	cleared := slices.Clone(rt.cleared)
	rt.pmu.Unlock()
	if !slices.ContainsFunc(cleared, func(v []string) bool { return slices.Equal(v, sb.NetworkAllowOut) }) {
		t.Fatalf("durable unfinished transition never tore down old policy after recovery and an acknowledged identical PUT; cleared=%v", cleared)
	}
}

// TestUnfinishedTransitionIsCompletedByRecovery (review 5 finding 3): a
// transition with no hold to show for it (a crash after the stored write)
// is found by its installed record and completed by the supervisor's
// recovery alone, and by reconcile alone; a completed one clears the
// record.
func TestUnfinishedTransitionIsCompletedByRecovery(t *testing.T) {
	for _, via := range []string{"supervisor", "reconcile"} {
		t.Run(via, func(t *testing.T) {
			svc, _, rt := newPolicyHarness(t)
			svc.cfg.EgressFQDNEnabled = false
			ctx := context.Background()
			sb := seedPolicySandbox(t, svc, models.Sandbox{NetworkAllowOut: []string{"8.8.8.0/24"}})
			next := *sb
			next.NetworkAllowOut = []string{"1.1.1.0/24"}
			st, _ := svc.store.GetEgressState(ctx, sb.ID)
			if err := svc.markTransition(ctx, sb, &next, st); err != nil {
				t.Fatal(err)
			}
			if err := svc.store.WriteNetworkPolicy(ctx, sb.ID, store.NetworkPolicyWrite{AllowOut: next.NetworkAllowOut, Inline: next.NetworkAllowOut}); err != nil {
				t.Fatal(err)
			}
			if via == "supervisor" {
				loop, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
				svc.SuperviseEgressGateway(loop, time.Millisecond)
				cancel()
			} else {
				rt.managed = map[string]*models.SandboxRuntimeState{sb.ID: {SandboxID: sb.ID, ContainerID: sb.ContainerID, ContainerIP: sb.ContainerIP, Status: models.SandboxStatusStarted}}
				if err := svc.Reconcile(ctx); err != nil {
					t.Fatal(err)
				}
			}
			rt.pmu.Lock()
			cleared := slices.Clone(rt.cleared)
			rt.pmu.Unlock()
			if !slices.ContainsFunc(cleared, func(v []string) bool { return slices.Equal(v, []string{"8.8.8.0/24"}) }) {
				t.Fatalf("the old rules must be torn down: cleared=%v", cleared)
			}
			if st, _ := svc.store.GetEgressState(ctx, sb.ID); st.Installed != nil {
				t.Fatalf("a completed transition clears its record: %+v", st.Installed)
			}
		})
	}
}

// TestStoppedTransitionKeepsItsRecord: a transition on a stopped container
// runs nothing live, so its record stays for the start and recovery to
// complete; and a stop whose rule clear fails records what is left against
// the address, not the sandbox (review 6 finding 4).
func TestStoppedTransitionKeepsItsRecord(t *testing.T) {
	svc, _, rt := newPolicyHarness(t)
	ctx := context.Background()
	sb := seedPolicySandbox(t, svc, models.Sandbox{NetworkAllowOut: []string{"8.8.8.0/24"}, Status: models.SandboxStatusStopped})
	if _, err := svc.UpdateNetworkPolicy(ctx, sb.ID, models.NetworkPolicyRequest{NetworkAllowOut: []string{"1.1.1.0/24"}}); err != nil {
		t.Fatal(err)
	}
	st, _ := svc.store.GetEgressState(ctx, sb.ID)
	if st.Installed == nil || len(st.Installed.CIDR) != 2 {
		t.Fatalf("a stopped transition keeps its record: %+v", st.Installed)
	}

	run := seedPolicySandbox(t, svc, models.Sandbox{ID: "run", NetworkAllowOut: []string{"9.9.9.0/24"}})
	rt.clearErr = errors.New("iptables busy")
	if err := svc.teardownSandboxEgress(ctx, run, "10.0.0.20"); err != nil {
		t.Fatal(err)
	}
	rt.clearErr = nil
	e, ok := svc.egressRuleClears.get(ruleClearKey{models.ContainerEngineDocker, "10.0.0.20"})
	if !ok || len(e.Rules) != 1 || e.Rules[0].Allow[0] != "9.9.9.0/24" || e.SandboxID != "run" {
		t.Fatalf("a failed stop clear must be recorded against the address: %+v %v", e, ok)
	}
	if st, _ := svc.store.GetEgressState(ctx, run.ID); st.Installed != nil {
		t.Fatalf("the rules moved to the address; the sandbox's record goes: %+v", st.Installed)
	}
}

// TestDestroyRuleClearIsRetried: a destroy whose rule clear fails leaves an
// entry the supervisor retries until it lands; if another sandbox holds the
// address by then, that sandbox is rebuilt, which clears the old rules
// under its swap block and puts its own back (review 6 finding 1).
func TestDestroyRuleClearIsRetried(t *testing.T) {
	svc, _, rt := newPolicyHarness(t)
	ctx := context.Background()
	key := ruleClearKey{models.ContainerEngineDocker, policyIP}
	sb := seedPolicySandbox(t, svc, models.Sandbox{NetworkAllowOut: []string{"9.9.9.0/24"}, AuditIncarnationID: "rule-clear"})
	rt.clearErr = errors.New("iptables busy")
	if err := svc.DestroySandbox(ctx, sb.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := svc.egressRuleClears.get(key); !ok {
		t.Fatal("a destroy's failed rule clear must be kept")
	}
	svc.retryRuleClears(ctx)
	if _, ok := svc.egressRuleClears.get(key); !ok {
		t.Fatal("a clear that still fails stays pending")
	}
	rt.clearErr = nil
	rt.pmu.Lock()
	rt.cleared = nil
	rt.pmu.Unlock()
	svc.retryRuleClears(ctx)
	rt.pmu.Lock()
	cleared := slices.Clone(rt.cleared)
	rt.pmu.Unlock()
	if _, ok := svc.egressRuleClears.get(key); ok || !slices.ContainsFunc(cleared, func(v []string) bool { return slices.Equal(v, []string{"9.9.9.0/24"}) }) {
		t.Fatalf("the retry must clear the rules: cleared=%v pending=%v", cleared, svc.egressRuleClears.snapshot())
	}
	if list, _ := svc.store.ListPendingEgressRuleClears(ctx); len(list) != 0 {
		t.Fatalf("a cleared entry leaves the store too: %+v", list)
	}

	// The address is someone else's now: it is rebuilt, not skipped.
	svc.egressRuleClears.put(store.PendingEgressRuleClear{Scope: key.scope, IP: key.ip, SandboxID: "old", Rules: []store.CIDRRules{{Allow: []string{"7.7.7.0/24"}}}})
	runningInRuntime(rt, seedPolicySandbox(t, svc, models.Sandbox{ID: "new-owner", NetworkAllowOut: []string{"1.1.1.0/24"}}))
	rt.pmu.Lock()
	rt.cleared, rt.applied = nil, nil
	rt.pmu.Unlock()
	svc.retryRuleClears(ctx)
	rt.pmu.Lock()
	cleared, applied := slices.Clone(rt.cleared), slices.Clone(rt.applied)
	rt.pmu.Unlock()
	has := func(l [][]string, v string) bool {
		return slices.ContainsFunc(l, func(x []string) bool { return slices.Equal(x, []string{v}) })
	}
	if _, ok := svc.egressRuleClears.get(key); ok || !has(cleared, "7.7.7.0/24") || !has(applied, "1.1.1.0/24") {
		t.Fatalf("the holder must be rebuilt: cleared=%v applied=%v pending=%v", cleared, applied, svc.egressRuleClears.snapshot())
	}
	if !rt.lifted(policyIP) {
		t.Fatal("the rebuild's swap block must be lifted")
	}
}

// TestDestroyTearsDownGatewayAndRulesTogether: an installed record naming a
// gateway and CIDR rules at once has both removed by an API destroy.
func TestDestroyTearsDownGatewayAndRulesTogether(t *testing.T) {
	svc, fake, rt := newPolicyHarness(t)
	ctx := context.Background()
	sb := seedPolicySandbox(t, svc, models.Sandbox{NetworkAllowOut: []string{"pypi.org"}, AuditIncarnationID: "both"})
	if err := svc.attachSandboxEgress(ctx, sb, rt); err != nil {
		t.Fatal(err)
	}
	if err := svc.store.SetInstalledEgress(ctx, sb.ID, store.InstalledEgress{Gateway: true, CIDR: []store.CIDRRules{{Allow: []string{"8.8.8.0/24"}}}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := svc.DestroySandbox(ctx, sb.ID); err != nil {
		t.Fatal(err)
	}
	rt.pmu.Lock()
	cleared := slices.Clone(rt.cleared)
	rt.pmu.Unlock()
	if fake.isAttached(sb.ID) || !slices.ContainsFunc(cleared, func(v []string) bool { return slices.Equal(v, []string{"8.8.8.0/24"}) }) {
		t.Fatalf("destroy must remove the gateway and the rules: attached=%v cleared=%v", fake.isAttached(sb.ID), cleared)
	}
}
