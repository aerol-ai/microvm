package service

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// Contract tests for the address ledger (egress_rule_clears.go) beyond the
// review 6 reproductions: every way an address changes hands, every exit
// path, a restart, and the cases where the ledger must wait rather than act.

// hasAllowRule reports the ACCEPT ApplyEgressPolicy installs for one
// allowed CIDR.
func hasAllowRule(be orderedRules, ip, cidr string) bool {
	ok, _ := be.Exists("filter", netrules.ChainDockerUser, "-s", ip, "-d", cidr, "-m", "comment", "--comment", "sbx-egress", "-j", "ACCEPT")
	return ok
}

func hasHoldDrop(be orderedRules, ip string) bool {
	ok, _ := be.Exists("filter", netrules.ChainDockerUser, "-s", ip, "-m", "comment", "--comment", "sbx-egress-hold", "-j", "DROP")
	return ok
}

// seedHolder stores a started sandbox at policyIP with its allowlist
// installed, as its create or start would have left it, and running there
// in the runtime's view.
func seedHolder(t *testing.T, svc *Service, rt *firewallRuntime, id, cidr string) *models.Sandbox {
	t.Helper()
	sb := seedPolicySandbox(t, svc, models.Sandbox{ID: id, NetworkAllowOut: []string{cidr}})
	if err := rt.ApplyEgressPolicy(policyIP, sb.NetworkAllowOut, nil); err != nil {
		t.Fatal(err)
	}
	runningInRuntime(rt.policyRuntime, sb)
	return sb
}

func runningInRuntime(rt *policyRuntime, sb *models.Sandbox) {
	if rt.inspect == nil {
		rt.inspect = map[string]*models.SandboxRuntimeState{}
	}
	rt.inspect[sb.ContainerID] = &models.SandboxRuntimeState{SandboxID: sb.ID, ContainerID: sb.ContainerID, ContainerIP: sb.ContainerIP, Status: models.SandboxStatusStarted}
}

// TestLateExitEventRebuildsTheAddressHolder: the address changed hands
// before the old sandbox's event was handled, so the old rules sit above the
// new owner's reused DROP. The event no longer skips them: the new owner is
// rebuilt, which removes them and puts its own back (review 6 finding 1).
func TestLateExitEventRebuildsTheAddressHolder(t *testing.T) {
	for _, exit := range []string{"destroy", "stop"} {
		t.Run(exit, func(t *testing.T) {
			svc, rt, be := firewallHarness(t)
			ctx := context.Background()
			old := seedOldAllowlist(t, svc, rt)
			seedHolder(t, svc, rt, "new", "1.1.1.0/24")
			if !be.permits(policyIP, "8.8.8.8") {
				t.Fatal("setup: the old ACCEPT must sit above the reused DROP")
			}
			var err error
			if exit == "destroy" {
				err = svc.handleDestroyEvent(ctx, old)
			} else {
				err = svc.markSandboxStopped(ctx, old, docker.DockerEvent{Action: "die"})
			}
			if err != nil {
				t.Fatal(err)
			}
			if be.permits(policyIP, "8.8.8.8") || !be.permits(policyIP, "1.1.1.1") {
				t.Fatalf("the holder must keep only its own allowlist: 8.8.8.8=%v 1.1.1.1=%v", be.permits(policyIP, "8.8.8.8"), be.permits(policyIP, "1.1.1.1"))
			}
			if len(svc.egressRuleClears.snapshot()) != 0 {
				t.Fatalf("the rebuild settles the entry: %v", svc.egressRuleClears.snapshot())
			}
		})
	}
}

// drivingRuntime puts a new container on ip and installs the requested
// policy, as the docker and containerd drivers do once it has its IP.
type drivingRuntime struct {
	*firewallRuntime
	ip         string
	afterRules func()
}

func (d drivingRuntime) Create(ctx context.Context, req models.CreateSandboxRequest, id, token string, binds []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	state, err := d.firewallRuntime.Create(ctx, req, id, token, binds)
	if err != nil {
		return nil, err
	}
	state.ContainerIP = d.ip
	if len(req.NetworkAllowOut) > 0 || len(req.NetworkDenyOut) > 0 {
		err = d.rules.ApplyEgressPolicy(state.ContainerIP, req.NetworkAllowOut, req.NetworkDenyOut)
	}
	if err == nil && d.afterRules != nil {
		d.afterRules()
	}
	return state, err
}

// TestCreateOnAnAddressWithLeftoversRebuildsIt: a new sandbox the runtime
// puts on an address with rules a destroyed one left is rebuilt before the
// create returns (review 6 finding 1, the create half).
func TestCreateOnAnAddressWithLeftoversRebuildsIt(t *testing.T) {
	svc, rt, be := firewallHarness(t)
	ctx := context.Background()
	old := seedOldAllowlist(t, svc, rt)
	rt.failClear = true
	if err := svc.DestroySandbox(ctx, old.ID); err != nil {
		t.Fatal(err)
	}
	rt.failClear = false
	svc.docker = drivingRuntime{firewallRuntime: rt, ip: policyIP}
	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", NetworkAllowOut: []string{"1.1.1.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	if be.permits(policyIP, "8.8.8.8") || !be.permits(policyIP, "1.1.1.1") {
		t.Fatalf("the new sandbox must have only its own allowlist: 8.8.8.8=%v 1.1.1.1=%v", be.permits(policyIP, "8.8.8.8"), be.permits(policyIP, "1.1.1.1"))
	}
	if len(svc.egressRuleClears.snapshot()) != 0 {
		t.Fatalf("the rebuild settles the entry: %v", svc.egressRuleClears.snapshot())
	}
	if st, _ := svc.store.GetEgressState(ctx, resp.Sandbox.ID); st.HoldReason != "" || st.Installed != nil {
		t.Fatalf("a clean rebuild leaves no hold or record: %+v", st)
	}
}

// TestHolderKeepsItsOwnHold: a leftover hold DROP is the holder's to keep
// when it is held itself, and goes when it isn't; the other rules go
// either way.
func TestHolderKeepsItsOwnHold(t *testing.T) {
	for _, held := range []bool{true, false} {
		name := "unheld"
		if held {
			name = "held"
		}
		t.Run(name, func(t *testing.T) {
			svc, rt, be := firewallHarness(t)
			ctx := context.Background()
			holder := seedHolder(t, svc, rt, "new", "1.1.1.0/24")
			if err := rt.ApplyEgressHold(policyIP); err != nil {
				t.Fatal(err)
			}
			if err := rt.ApplyEgressPolicy(policyIP, []string{"8.8.8.0/24"}, nil); err != nil {
				t.Fatal(err)
			}
			if held {
				if err := svc.store.SetEgressHold(ctx, holder.ID, egressHoldProfileUnavailable, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			svc.egressRuleClears.put(store.PendingEgressRuleClear{Scope: models.ContainerEngineDocker, IP: policyIP, SandboxID: "old",
				Rules: []store.CIDRRules{{Allow: []string{"8.8.8.0/24"}}}, Hold: true})
			if err := svc.clearPendingFor(ctx, rt, holder); err != nil {
				t.Fatal(err)
			}
			if hasAllowRule(be, policyIP, "8.8.8.0/24") {
				t.Fatal("the old ACCEPT must go")
			}
			if hasHoldDrop(be, policyIP) != held {
				t.Fatalf("hold DROP present=%v, want %v", hasHoldDrop(be, policyIP), held)
			}
			if len(svc.egressRuleClears.snapshot()) != 0 {
				t.Fatalf("nothing is left to clear: %v", svc.egressRuleClears.snapshot())
			}
		})
	}
}

// ownerRuntimeView adds the runtime's own view of who holds an address.
type ownerRuntimeView struct {
	*firewallRuntime
	owner string
}

func (o ownerRuntimeView) IPOwner(context.Context, string) (string, error) { return o.owner, nil }

// TestDisputedAddressWaits: when the holder can't be settled (two rows
// claim the address, or the store names a sandbox the runtime doesn't have
// there), the retry neither clears nor rebuilds; it waits.
func TestDisputedAddressWaits(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rows  []string
		owner string // the runtime's view; "-" for a runtime that can't tell
	}{
		{"two claimants", []string{"a", "b"}, "-"},
		{"row without a container", []string{"a"}, ""},
		{"runtime disagrees", []string{"a"}, "b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, rt, be := firewallHarness(t)
			ctx := context.Background()
			for _, id := range tc.rows {
				seedPolicySandbox(t, svc, models.Sandbox{ID: id, NetworkAllowOut: []string{"1.1.1.0/24"}})
			}
			if tc.owner != "-" {
				svc.docker = ownerRuntimeView{rt, tc.owner}
			}
			if err := rt.ApplyEgressPolicy(policyIP, []string{"8.8.8.0/24"}, nil); err != nil {
				t.Fatal(err)
			}
			k := ruleClearKey{models.ContainerEngineDocker, policyIP}
			svc.egressRuleClears.put(store.PendingEgressRuleClear{Scope: k.scope, IP: k.ip, SandboxID: "old", Rules: []store.CIDRRules{{Allow: []string{"8.8.8.0/24"}}}})
			svc.retryRuleClears(ctx)
			if _, ok := svc.egressRuleClears.get(k); !ok || !hasAllowRule(be, policyIP, "8.8.8.0/24") {
				t.Fatal("a disputed address must be left as it is")
			}
		})
	}
}

// TestMissedStopIsTornDownByReconcile: a row that says started while its
// container stopped or moved missed the stop; reconcile tears down what it
// left at the old address before the row forgets it (review 6 finding 4).
func TestMissedStopIsTornDownByReconcile(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status models.SandboxStatus
		ip     string
	}{
		{"stopped", models.SandboxStatusStopped, policyIP},
		{"moved", models.SandboxStatusStarted, "10.0.0.21"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, rt, be := firewallHarness(t)
			ctx := context.Background()
			sb := seedOldAllowlist(t, svc, rt)
			rt.managed = map[string]*models.SandboxRuntimeState{sb.ID: {SandboxID: sb.ID, ContainerID: sb.ContainerID, ContainerIP: tc.ip, Status: tc.status}}
			if err := svc.Reconcile(ctx); err != nil {
				t.Fatal(err)
			}
			if hasAllowRule(be, policyIP, "8.8.8.0/24") {
				t.Fatal("the old address must be cleared")
			}
			if tc.status == models.SandboxStatusStarted && !hasAllowRule(be, tc.ip, "8.8.8.0/24") {
				t.Fatal("the new address must be enforced")
			}
			if len(svc.egressRuleClears.snapshot()) != 0 {
				t.Fatalf("nothing is left: %v", svc.egressRuleClears.snapshot())
			}
		})
	}
}

// TestStartEventAtANewAddressTearsDownTheOld: a start event finds the row
// still started at another address (its stop was missed): the old address
// is cleared before the new one is enforced.
func TestStartEventAtANewAddressTearsDownTheOld(t *testing.T) {
	svc, rt, be := firewallHarness(t)
	ctx := context.Background()
	sb := seedOldAllowlist(t, svc, rt)
	rt.inspect = map[string]*models.SandboxRuntimeState{sb.ContainerID: {SandboxID: sb.ID, ContainerID: sb.ContainerID, ContainerIP: "10.0.0.21", Status: models.SandboxStatusStarted}}
	if err := svc.handleStartEvent(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if hasAllowRule(be, policyIP, "8.8.8.0/24") || !hasAllowRule(be, "10.0.0.21", "8.8.8.0/24") {
		t.Fatalf("old cleared=%v new enforced=%v", !hasAllowRule(be, policyIP, "8.8.8.0/24"), hasAllowRule(be, "10.0.0.21", "8.8.8.0/24"))
	}
}

// TestStartAdoptsThePolicyStoredMeanwhile: the start enforces the stored
// policy read under the policy lock, not the one its caller read earlier,
// and hands it back so the caller's row write keeps it.
func TestStartAdoptsThePolicyStoredMeanwhile(t *testing.T) {
	svc, rt, be := firewallHarness(t)
	ctx := context.Background()
	stale := seedPolicySandbox(t, svc, models.Sandbox{NetworkAllowOut: []string{"8.8.8.0/24"}, Status: models.SandboxStatusStopped})
	if err := svc.store.WriteNetworkPolicy(ctx, stale.ID, store.NetworkPolicyWrite{AllowOut: []string{"1.1.1.0/24"}, Inline: []string{"1.1.1.0/24"}}); err != nil {
		t.Fatal(err)
	}
	stale.Status = models.SandboxStatusStarted
	if err := svc.enforceEgressOnStart(ctx, rt, stale); err != nil {
		t.Fatal(err)
	}
	if be.permits(policyIP, "8.8.8.8") || !be.permits(policyIP, "1.1.1.1") {
		t.Fatal("the start must enforce the stored policy")
	}
	if !slices.Equal(stale.NetworkAllowOut, []string{"1.1.1.0/24"}) {
		t.Fatalf("the caller's copy must carry the stored policy: %v", stale.NetworkAllowOut)
	}
}

// TestGatewayStartWithLeftoversStartsHeld: a gateway-mode start that has to
// rebuild and whose attach fails starts shut and held, as a plain start
// whose attach fails does, rather than being stopped.
func TestGatewayStartWithLeftoversStartsHeld(t *testing.T) {
	svc, gw, rt := newPolicyHarness(t)
	ctx := context.Background()
	sb := seedPolicySandbox(t, svc, models.Sandbox{NetworkAllowOut: []string{"pypi.org"}})
	svc.egressRuleClears.put(store.PendingEgressRuleClear{Scope: models.ContainerEngineDocker, IP: policyIP, SandboxID: "old", Rules: []store.CIDRRules{{Allow: []string{"8.8.8.0/24"}}}})
	gw.attachErr = errors.New("gateway down")
	if err := svc.enforceEgressOnStart(ctx, rt, sb); err != nil {
		t.Fatalf("the start must succeed held: %v", err)
	}
	if st, _ := svc.store.GetEgressState(ctx, sb.ID); st.HoldReason != egressHoldApplyFailed {
		t.Fatalf("hold = %q, want %q", st.HoldReason, egressHoldApplyFailed)
	}
	if len(svc.egressRuleClears.snapshot()) != 0 {
		t.Fatalf("the leftovers go before the attach: %v", svc.egressRuleClears.snapshot())
	}
}

// TestDestroyKeepsItsRowWhileTheLedgerRefuses: a destroy whose leftover
// rules the store won't record keeps its row, the retry anchor, and this
// process still retries the rules; one whose rules all cleared doesn't
// need the ledger and completes.
func TestDestroyKeepsItsRowWhileTheLedgerRefuses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	base := &policyRuntime{holdRuntime: &holdRuntime{recordingRuntime: &recordingRuntime{}}}
	svc, _, _ := newServiceRuntimeHarnessAtPath(t, path, base)
	svc.cfg.EgressFQDNEnabled = false
	be := orderedRules{}
	rt := &firewallRuntime{policyRuntime: base, rules: netrules.NewWithBackend(be)}
	svc.docker = rt
	ctx := context.Background()
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TRIGGER refuse_pending BEFORE INSERT ON pending_egress_rule_clears BEGIN SELECT RAISE(ABORT, 'disk full'); END`); err != nil {
		t.Fatal(err)
	}

	sb := seedOldAllowlist(t, svc, rt)
	rt.failClear = true
	if err := svc.DestroySandbox(ctx, sb.ID); err == nil {
		t.Fatal("a destroy whose leftovers aren't recorded must fail")
	}
	if _, err := svc.store.Get(ctx, sb.ID); err != nil {
		t.Fatalf("the row must stay: %v", err)
	}
	if _, ok := svc.egressRuleClears.get(ruleClearKey{models.ContainerEngineDocker, policyIP}); !ok {
		t.Fatal("this process still holds what the store refused")
	}
	// The row still claims the address but its container is gone: the
	// retry waits rather than put the rules back (runningAt).
	rt.failClear = false
	svc.retryRuleClears(ctx)
	if !hasAllowRule(be, policyIP, "8.8.8.0/24") {
		t.Fatal("the retry must not act for a row whose container is gone")
	}
	if !be.permits(policyIP, "8.8.8.8") || be.permits(policyIP, "1.1.1.1") {
		t.Fatal("nor reinstall the gone sandbox's rules")
	}
	// The retried destroy, from the row it kept, finishes the job.
	if err := svc.DestroySandbox(ctx, sb.ID); err != nil {
		t.Fatalf("a retried destroy completes once its rules clear: %v", err)
	}
	if hasAllowRule(be, policyIP, "8.8.8.0/24") {
		t.Fatal("the retried destroy clears the rules")
	}

	clean := seedPolicySandbox(t, svc, models.Sandbox{ID: "clean", NetworkAllowOut: []string{"9.9.9.0/24"}, AuditIncarnationID: "clean"})
	if err := svc.DestroySandbox(ctx, clean.ID); err != nil {
		t.Fatalf("nothing left, nothing to record: %v", err)
	}
}

// TestRuleScopes: Firecracker rules live in its own firewall; a container's
// in its engine's, with the default engine for a row that names none. An
// address whose firewall isn't there is recorded and left for the retry.
func TestRuleScopes(t *testing.T) {
	for _, tc := range []struct {
		sb   models.Sandbox
		want string
	}{
		{models.Sandbox{Runtime: models.RuntimeFirecracker}, models.RuntimeFirecracker},
		{models.Sandbox{Runtime: models.RuntimeDocker}, models.ContainerEngineDocker},
		{models.Sandbox{Runtime: models.RuntimeDocker, Engine: models.ContainerEngineContainerd}, models.ContainerEngineContainerd},
	} {
		if got := ruleScope(&tc.sb); got != tc.want {
			t.Fatalf("ruleScope(%+v) = %q, want %q", tc.sb, got, tc.want)
		}
	}
	svc, _, _ := firewallHarness(t)
	ctx := context.Background()
	vm := &models.Sandbox{ID: "vm", Runtime: models.RuntimeFirecracker, NetworkAllowOut: []string{"8.8.8.0/24"}}
	if err := svc.teardownSandboxEgress(ctx, vm, "10.1.0.2"); err != nil {
		t.Fatal(err)
	}
	if _, ok := svc.egressRuleClears.get(ruleClearKey{models.RuntimeFirecracker, "10.1.0.2"}); !ok {
		t.Fatal("rules in a firewall that isn't there are kept for the retry")
	}
	svc.retryRuleClears(ctx)
	if _, ok := svc.egressRuleClears.get(ruleClearKey{models.RuntimeFirecracker, "10.1.0.2"}); !ok {
		t.Fatal("still kept")
	}
}

// TestLedgerSurvivesARestartForCreates: a fresh process reads the ledger the
// first time a create asks, so a new sandbox on a dirty address is rebuilt
// even before the supervisor's first pass.
func TestLedgerSurvivesARestartForCreates(t *testing.T) {
	svc, rt, be := firewallHarness(t)
	ctx := context.Background()
	old := seedOldAllowlist(t, svc, rt)
	rt.failClear = true
	if err := svc.DestroySandbox(ctx, old.ID); err != nil {
		t.Fatal(err)
	}
	rt.failClear = false
	fresh := New(svc.cfg, svc.logger, svc.store, rt, nil, svc.caddy, svc.cipher, svc.mounts, nil)
	next := seedHolder(t, fresh, rt, "new", "1.1.1.0/24")
	fresh.settleEnforcedEgress(ctx, next, fresh.egressClears.now())
	if be.permits(policyIP, "8.8.8.8") || !be.permits(policyIP, "1.1.1.1") {
		t.Fatal("the fresh process must rebuild the new sandbox from the stored ledger")
	}
}

// TestClearDuringCreateIsCaught: a late stop event clears the old sandbox's
// address after the new sandbox's driver installed its rules there but
// before its row carries the address, so nothing showed the new owner and
// the clear removed the catch-all DROP both share. The create's check finds
// the clear in the log and rebuilds the new sandbox (egressClearLog).
func TestClearDuringCreateIsCaught(t *testing.T) {
	svc, rt, be := firewallHarness(t)
	ctx := context.Background()
	old := seedOldAllowlist(t, svc, rt)
	svc.docker = drivingRuntime{firewallRuntime: rt, ip: policyIP, afterRules: func() {
		if err := svc.markSandboxStopped(ctx, old, docker.DockerEvent{Action: "die"}); err != nil {
			t.Error(err)
		}
		if !be.permits(policyIP, "9.9.9.9") {
			t.Error("setup: the late clear must have removed the shared DROP")
		}
	}}
	if _, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{Image: "alpine", NetworkAllowOut: []string{"1.1.1.0/24"}}); err != nil {
		t.Fatal(err)
	}
	if be.permits(policyIP, "9.9.9.9") || be.permits(policyIP, "8.8.8.8") || !be.permits(policyIP, "1.1.1.1") {
		t.Fatalf("the new sandbox must be back on its own allowlist: 9.9.9.9=%v 8.8.8.8=%v 1.1.1.1=%v",
			be.permits(policyIP, "9.9.9.9"), be.permits(policyIP, "8.8.8.8"), be.permits(policyIP, "1.1.1.1"))
	}
}

// TestClearLogReach: the log answers for the clears it holds and says yes
// once the clears since the caller's generation outnumber it.
func TestClearLogReach(t *testing.T) {
	var l egressClearLog
	a, b := ruleClearKey{"docker", "10.0.0.1"}, ruleClearKey{"docker", "10.0.0.2"}
	g0 := l.now()
	if l.clearedSince(a, g0) {
		t.Fatal("nothing cleared yet")
	}
	l.mark(b)
	if l.clearedSince(a, g0) || !l.clearedSince(b, g0) {
		t.Fatal("only b was cleared")
	}
	g1 := l.now()
	for range len(l.ring) + 1 {
		l.mark(b)
	}
	if !l.clearedSince(a, g1) {
		t.Fatal("past the log's reach it must say yes")
	}
}
