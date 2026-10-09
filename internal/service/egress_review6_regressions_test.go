package service

// Regression tests from the sixth review of PR #622: each reproduces a
// finding against the reviewed head (87e02279) through production service
// code and the real netrules.Manager, over an ordered in-memory rule
// backend, and passes with its fix.

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Real netrules.Manager over an ordered in-memory RuleBackend: service
// lifecycle paths and firewall rule generation are production code.
type orderedRules map[string][][]string

func (b orderedRules) EnsureInputChain(string) error { return nil }
func (b orderedRules) Exists(table, chain string, spec ...string) (bool, error) {
	return slices.ContainsFunc(b[table+chain], func(s []string) bool { return slices.Equal(s, spec) }), nil
}
func (b orderedRules) Insert(table, chain string, pos int, spec ...string) error {
	k := table + chain
	at := min(max(pos-1, 0), len(b[k]))
	b[k] = slices.Insert(b[k], at, slices.Clone(spec))
	return nil
}
func (b orderedRules) Delete(table, chain string, spec ...string) error {
	k := table + chain
	at := slices.IndexFunc(b[k], func(s []string) bool { return slices.Equal(s, spec) })
	if at < 0 {
		return errors.New("rule does not exist")
	}
	b[k] = slices.Delete(b[k], at, at+1)
	return nil
}
func (b orderedRules) permits(ip, dst string) bool {
	for _, rule := range b["filter"+netrules.ChainDockerUser] {
		matches, verdict := true, ""
		for i := 0; i+1 < len(rule); i++ {
			switch rule[i] {
			case "-s":
				matches = matches && rule[i+1] == ip
			case "-d":
				matches = matches && netip.MustParsePrefix(rule[i+1]).Contains(netip.MustParseAddr(dst))
			case "-j":
				verdict = rule[i+1]
			}
		}
		if matches && (verdict == "ACCEPT" || verdict == "DROP") {
			return verdict == "ACCEPT"
		}
	}
	return true
}

type firewallRuntime struct {
	*policyRuntime
	rules     *netrules.Manager
	failClear bool
}

func (r *firewallRuntime) ApplyEgressPolicy(ip string, allow, deny []string) error {
	return r.rules.ApplyEgressPolicy(ip, allow, deny)
}
func (r *firewallRuntime) ClearEgressPolicy(ip string, allow, deny []string) error {
	if r.failClear {
		return errors.New("iptables temporarily busy")
	}
	return r.rules.ClearEgressPolicy(ip, allow, deny)
}
func (r *firewallRuntime) ClearNetworkRules(ip string) error {
	return r.rules.ClearBlockAllEgress(ip)
}
func (r *firewallRuntime) ApplyNetworkBlockAll(ip string) error {
	return r.rules.BlockAllEgress(ip)
}
func (r *firewallRuntime) ClearNetworkBlockEgress(ip string) error {
	return r.rules.ClearBlockAllEgress(ip)
}
func (r *firewallRuntime) ApplyEgressHold(ip string) error { return r.rules.HoldEgress(ip) }
func (r *firewallRuntime) ClearEgressHold(ip string) error { return r.rules.ClearHoldEgress(ip) }

func firewallHarness(t *testing.T) (*Service, *firewallRuntime, orderedRules) {
	svc, _, old := newPolicyHarness(t)
	svc.cfg.EgressFQDNEnabled = false
	be := orderedRules{}
	rt := &firewallRuntime{policyRuntime: old, rules: netrules.NewWithBackend(be)}
	svc.docker = rt
	return svc, rt, be
}
func seedOldAllowlist(t *testing.T, svc *Service, rt *firewallRuntime) *models.Sandbox {
	sb := seedPolicySandbox(t, svc, models.Sandbox{ID: "old", NetworkAllowOut: []string{"8.8.8.0/24"}, AuditIncarnationID: "review6-old"})
	if err := rt.ApplyEgressPolicy(policyIP, sb.NetworkAllowOut, nil); err != nil {
		t.Fatal(err)
	}
	return sb
}

func TestDestroyedRuleClearSurvivesServiceRestart(t *testing.T) {
	svc, rt, be := firewallHarness(t)
	ctx := context.Background()
	sb := seedOldAllowlist(t, svc, rt)
	rt.failClear = true
	if err := svc.DestroySandbox(ctx, sb.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.store.Get(ctx, sb.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("row not deleted: %v", err)
	}
	if len(svc.egressRuleClears.snapshot()) != 1 {
		t.Fatal("setup: expected pending clear")
	}
	rt.failClear = false
	// Restart boundary: a new Service with the same SQLite and host firewall,
	// with none of the old Service's in-memory maps.
	fresh := New(svc.cfg, svc.logger, svc.store, rt, nil, svc.caddy, svc.cipher, svc.mounts, nil)
	loop, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	fresh.SuperviseEgressGateway(loop, time.Millisecond)
	cancel()
	if err := fresh.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	oldRule, _ := be.Exists("filter", netrules.ChainDockerUser, "-s", policyIP, "-d", "8.8.8.0/24", "-m", "comment", "--comment", "sbx-egress", "-j", "ACCEPT")
	if oldRule {
		t.Fatal("old ACCEPT survives service restart: sandbox row and the only clear intent are gone")
	}
}

func TestIPReuseDoesNotInheritDestroyedAllowlist(t *testing.T) {
	svc, rt, be := firewallHarness(t)
	ctx := context.Background()
	sb := seedOldAllowlist(t, svc, rt)
	rt.failClear = true
	if err := svc.DestroySandbox(ctx, sb.ID); err != nil {
		t.Fatal(err)
	}
	rt.failClear = false
	next := seedPolicySandbox(t, svc, models.Sandbox{ID: "new", NetworkAllowOut: []string{"1.1.1.0/24"}})
	if err := svc.reapplyEgressOnStart(ctx, rt, next); err != nil {
		t.Fatal(err)
	}
	svc.retryRuleClears(ctx)
	rt.managed = map[string]*models.SandboxRuntimeState{next.ID: {SandboxID: next.ID, ContainerID: next.ContainerID, ContainerIP: policyIP, Status: models.SandboxStatusStarted}}
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if be.permits(policyIP, "8.8.8.8") {
		t.Fatalf("new sandbox permits old owner's 8.8.8.8 outside its 1.1.1.0/24 allowlist; pending=%v", svc.egressRuleClears.snapshot())
	}
}

func TestStoppedClearKeepsOriginalIPThroughRestart(t *testing.T) {
	svc, rt, be := firewallHarness(t)
	ctx := context.Background()
	sb := seedOldAllowlist(t, svc, rt)
	rt.failClear = true
	if err := svc.markSandboxStopped(ctx, sb, docker.DockerEvent{Action: "die"}); err != nil {
		t.Fatal(err)
	}
	rt.failClear = false
	// The failed clear's rules are recorded against the address they are
	// at, not left in the sandbox's record, which only describes its
	// current address (the reviewer's setup asserted the record).
	if list, err := svc.store.ListPendingEgressRuleClears(ctx); err != nil || len(list) != 1 || list[0].IP != policyIP {
		t.Fatalf("setup: rules not recorded at the original address: %+v %v", list, err)
	}
	rt.inspect = map[string]*models.SandboxRuntimeState{sb.ContainerID: {SandboxID: sb.ID, ContainerID: sb.ContainerID, ContainerIP: "10.0.0.21", Status: models.SandboxStatusStarted}}
	if err := svc.handleStartEvent(ctx, sb); err != nil {
		t.Fatal(err)
	}
	// Recovery now applies/clears the journal against the new IP.
	svc.egressApplyIdle.Store(false)
	svc.retryUnappliedPolicies(ctx)
	st, err := svc.store.GetEgressState(ctx, sb.ID)
	if err != nil {
		t.Fatal(err)
	}
	oldRule, _ := be.Exists("filter", netrules.ChainDockerUser, "-s", policyIP, "-d", "8.8.8.0/24", "-m", "comment", "--comment", "sbx-egress", "-j", "ACCEPT")
	if oldRule {
		t.Fatalf("old IP still has ACCEPT after successful recovery at new IP; unfinished record=%+v", st.Installed)
	}
}

func TestStartCompletesStoppedPolicyTransitionBeforeSuccess(t *testing.T) {
	svc, rt, be := firewallHarness(t)
	ctx := context.Background()
	sb := seedOldAllowlist(t, svc, rt)
	rt.failClear = true
	if err := svc.markSandboxStopped(ctx, sb, docker.DockerEvent{Action: "die"}); err != nil {
		t.Fatal(err)
	}
	rt.failClear = false
	if _, err := svc.UpdateNetworkPolicy(ctx, sb.ID, models.NetworkPolicyRequest{NetworkAllowOut: []string{"1.1.1.0/24"}}); err != nil {
		t.Fatal(err)
	}
	row, err := svc.store.Get(ctx, sb.ID)
	if err != nil {
		t.Fatal(err)
	}
	rt.inspect = map[string]*models.SandboxRuntimeState{sb.ContainerID: {SandboxID: sb.ID, ContainerID: sb.ContainerID, ContainerIP: policyIP, Status: models.SandboxStatusStarted}}
	if err := svc.handleStartEvent(ctx, row); err != nil {
		t.Fatal(err)
	}
	if be.permits(policyIP, "8.8.8.8") {
		t.Fatal("start acknowledged with old 8.8.8.8 still permitted outside current 1.1.1.0/24 allowlist")
	}
}

// Controls check that the same adapter removes rules when the production
// cleanup is actually reached, and interprets the new allowlist correctly.
func TestRuleClearCleanupControls(t *testing.T) {
	for _, transient := range []bool{false, true} {
		name := "successful-destroy"
		if transient {
			name = "failed-destroy-then-successful-retry"
		}
		t.Run(name, func(t *testing.T) {
			svc, rt, be := firewallHarness(t)
			ctx := context.Background()
			sb := seedOldAllowlist(t, svc, rt)
			rt.failClear = transient
			if err := svc.DestroySandbox(ctx, sb.ID); err != nil {
				t.Fatal(err)
			}
			rt.failClear = false
			svc.retryRuleClears(ctx)
			next := seedPolicySandbox(t, svc, models.Sandbox{ID: "new", NetworkAllowOut: []string{"1.1.1.0/24"}})
			if err := svc.reapplyEgressOnStart(ctx, rt, next); err != nil {
				t.Fatal(err)
			}
			if be.permits(policyIP, "8.8.8.8") || !be.permits(policyIP, "1.1.1.1") {
				t.Fatal("control: expected only new allowlist once cleanup succeeds before IP reuse")
			}
		})
	}
}
