package service

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/egress"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// policyRuntime records the selective-egress calls a policy transition makes
// and can fail any step of it.
type policyRuntime struct {
	*holdRuntime
	pmu        sync.Mutex
	applied    [][]string
	cleared    [][]string
	blockErr   error
	clearErr   error
	applyErr   error
	liftErr    error
	blockCalls int
	pid        int
	pidErr     error
}

// ContainerPID stands in for the drivers' init-pid lookup (P3-3).
func (p *policyRuntime) ContainerPID(context.Context, string) (int, error) {
	return p.pid, p.pidErr
}

func (p *policyRuntime) ApplyEgressPolicy(_ string, allow, _ []string) error {
	p.pmu.Lock()
	defer p.pmu.Unlock()
	p.applied = append(p.applied, allow)
	return p.applyErr
}

func (p *policyRuntime) ClearEgressPolicy(_ string, allow, _ []string) error {
	p.pmu.Lock()
	defer p.pmu.Unlock()
	p.cleared = append(p.cleared, allow)
	return p.clearErr
}

func (p *policyRuntime) ApplyNetworkBlockAll(ip string) error {
	p.pmu.Lock()
	p.blockCalls++
	p.pmu.Unlock()
	if p.blockErr != nil {
		return p.blockErr
	}
	return p.holdRuntime.ApplyNetworkBlockAll(ip)
}

func (p *policyRuntime) ClearNetworkBlockEgress(ip string) error {
	if p.liftErr != nil {
		return p.liftErr
	}
	return p.holdRuntime.ClearNetworkBlockEgress(ip)
}

func (p *policyRuntime) lifted(ip string) bool {
	return slices.Contains(p.clearNetworkBlockEgresses, ip)
}

func newPolicyHarness(t *testing.T) (*Service, *fakeGateway, *policyRuntime) {
	t.Helper()
	rt := &policyRuntime{holdRuntime: &holdRuntime{recordingRuntime: &recordingRuntime{}}}
	svc, _, _ := newServiceRuntimeHarnessAtPath(t, filepath.Join(t.TempDir(), "state.db"), rt)
	svc.cfg.EgressFQDNEnabled = true
	gw := newFakeGateway()
	gw.events = make(chan egress.Event)
	svc.SetEgressGateway(gw, func(context.Context) []egress.Bridge {
		return []egress.Bridge{{Name: "docker0", GatewayIP: netip.MustParseAddr("172.17.0.1")}}
	})
	return svc, gw, rt
}

const policyIP = "10.0.0.20"

func seedPolicySandbox(t *testing.T, svc *Service, sb models.Sandbox) *models.Sandbox {
	t.Helper()
	now := time.Now().UTC()
	if sb.ID == "" {
		sb.ID = "sb-pol"
	}
	if sb.Runtime == "" {
		sb.Runtime = models.RuntimeDocker
	}
	if sb.Status == "" {
		sb.Status = models.SandboxStatusStarted
	}
	sb.Image, sb.ContainerID, sb.ContainerIP = "alpine", "ctr-"+sb.ID, policyIP
	sb.CreatedAt, sb.UpdatedAt, sb.LastActiveAt = now, now, now
	if err := svc.store.Create(context.Background(), &sb); err != nil {
		t.Fatal(err)
	}
	return &sb
}

// TestUpdateNetworkPolicyTransitions walks the §5.8 table on a running
// container: every swap happens under a block-all DROP, the old mode is torn
// down, the new one put in place, and the DROP lifted unless the new policy
// is block-all.
func TestUpdateNetworkPolicyTransitions(t *testing.T) {
	type state struct {
		block bool
		allow []string
	}
	for _, tc := range []struct {
		name         string
		from, to     state
		wantAttach   bool
		wantDetach   bool
		wantApplied  []string
		wantCleared  []string
		wantLifted   bool
		wantStatus   string
		wantGWPolicy []string
	}{
		{name: "none to hostname", to: state{allow: []string{"pypi.org"}}, wantAttach: true, wantLifted: true, wantStatus: EgressStatusActive, wantGWPolicy: []string{"pypi.org"}},
		{name: "cidr to hostname", from: state{allow: []string{"1.1.1.0/24"}}, to: state{allow: []string{"pypi.org"}}, wantAttach: true, wantCleared: []string{"1.1.1.0/24"}, wantLifted: true, wantStatus: EgressStatusActive, wantGWPolicy: []string{"pypi.org"}},
		{name: "hostname to hostname", from: state{allow: []string{"pypi.org"}}, to: state{allow: []string{"github.com"}}, wantAttach: true, wantLifted: true, wantStatus: EgressStatusActive, wantGWPolicy: []string{"github.com"}},
		{name: "hostname to cidr", from: state{allow: []string{"pypi.org"}}, to: state{allow: []string{"1.1.1.0/24"}}, wantDetach: true, wantApplied: []string{"1.1.1.0/24"}, wantLifted: true},
		{name: "hostname to block-all", from: state{allow: []string{"pypi.org"}}, to: state{block: true}, wantDetach: true},
		{name: "cidr to none", from: state{allow: []string{"1.1.1.0/24"}}, to: state{}, wantCleared: []string{"1.1.1.0/24"}, wantLifted: true},
		{name: "block-all to cidr", from: state{block: true}, to: state{allow: []string{"1.1.1.0/24"}}, wantApplied: []string{"1.1.1.0/24"}, wantLifted: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, gw, rt := newPolicyHarness(t)
			ctx := context.Background()
			seedPolicySandbox(t, svc, models.Sandbox{NetworkBlockAll: tc.from.block, NetworkAllowOut: tc.from.allow})
			got, err := svc.UpdateNetworkPolicy(ctx, "sb-pol", models.NetworkPolicyRequest{NetworkBlockAll: tc.to.block, NetworkAllowOut: tc.to.allow})
			if err != nil {
				t.Fatal(err)
			}
			if rt.blockCalls == 0 {
				t.Fatal("the swap must start with a block-all DROP")
			}
			if gw.isAttached("sb-pol") != tc.wantAttach {
				t.Fatalf("attached = %v, want %v", gw.isAttached("sb-pol"), tc.wantAttach)
			}
			if tc.wantGWPolicy != nil && !slices.Equal(gw.attached["sb-pol"].AllowOut, tc.wantGWPolicy) {
				t.Fatalf("gateway policy = %v", gw.attached["sb-pol"].AllowOut)
			}
			if slices.Contains(gw.detached, "sb-pol") != tc.wantDetach {
				t.Fatalf("detached = %v, want %v", gw.detached, tc.wantDetach)
			}
			if tc.wantApplied != nil && (len(rt.applied) != 1 || !slices.Equal(rt.applied[0], tc.wantApplied)) {
				t.Fatalf("applied = %v", rt.applied)
			}
			if tc.wantApplied == nil && len(rt.applied) != 0 {
				t.Fatalf("unexpected netrules apply %v", rt.applied)
			}
			if tc.wantCleared != nil && (len(rt.cleared) != 1 || !slices.Equal(rt.cleared[0], tc.wantCleared)) {
				t.Fatalf("cleared = %v", rt.cleared)
			}
			if rt.lifted(policyIP) != tc.wantLifted {
				t.Fatalf("lifted = %v, want %v", rt.lifted(policyIP), tc.wantLifted)
			}
			if got.EgressStatus != tc.wantStatus || got.NetworkBlockAll != tc.to.block || !slices.Equal(got.NetworkAllowOut, tc.to.allow) {
				t.Fatalf("effective policy = %+v", got)
			}
			row, _ := svc.store.Get(ctx, "sb-pol")
			if row.NetworkBlockAll != tc.to.block || !slices.Equal(row.NetworkAllowOut, tc.to.allow) {
				t.Fatalf("stored row = block %v allow %v", row.NetworkBlockAll, row.NetworkAllowOut)
			}
		})
	}
}

// TestUpdateNetworkPolicyIdempotent: the same body twice is a no-op, unless
// the sandbox is held, when it is the retry that converges.
func TestUpdateNetworkPolicyIdempotent(t *testing.T) {
	svc, gw, rt := newPolicyHarness(t)
	ctx := context.Background()
	seedPolicySandbox(t, svc, models.Sandbox{NetworkAllowOut: []string{"pypi.org"}})
	req := models.NetworkPolicyRequest{NetworkAllowOut: []string{"pypi.org"}}
	if _, err := svc.UpdateNetworkPolicy(ctx, "sb-pol", req); err != nil {
		t.Fatal(err)
	}
	if rt.blockCalls != 0 || gw.isAttached("sb-pol") {
		t.Fatal("an unchanged policy must not touch the runtime or the gateway")
	}
	if err := svc.store.SetEgressHold(ctx, "sb-pol", egressHoldAttachFailed, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	got, err := svc.UpdateNetworkPolicy(ctx, "sb-pol", req)
	if err != nil {
		t.Fatal(err)
	}
	if !gw.isAttached("sb-pol") || got.EgressStatus != EgressStatusActive {
		t.Fatalf("a held sandbox must re-attach on retry: attached=%v status=%q", gw.isAttached("sb-pol"), got.EgressStatus)
	}
	if st, _ := svc.store.GetEgressState(ctx, "sb-pol"); st.HoldReason != "" {
		t.Fatal("the retry must release the hold")
	}
}

// TestUpdateNetworkPolicyAttachFailureHolds: the policy is stored, the
// sandbox is held (D16) and the call answers apply_failed_held.
func TestUpdateNetworkPolicyAttachFailureHolds(t *testing.T) {
	svc, gw, rt := newPolicyHarness(t)
	ctx := context.Background()
	seedPolicySandbox(t, svc, models.Sandbox{})
	gw.attachErr = egress.ErrUnavailable
	_, err := svc.UpdateNetworkPolicy(ctx, "sb-pol", models.NetworkPolicyRequest{NetworkAllowOut: []string{"pypi.org"}})
	if !errors.Is(err, ErrEgressApplyFailedHeld) {
		t.Fatalf("err = %v, want apply_failed_held", err)
	}
	row, _ := svc.store.Get(ctx, "sb-pol")
	if !slices.Equal(row.NetworkAllowOut, []string{"pypi.org"}) {
		t.Fatal("the store is the source of truth: the new policy must be kept")
	}
	if st, _ := svc.store.GetEgressState(ctx, "sb-pol"); st.HoldReason != egressHoldApplyFailed {
		t.Fatalf("hold = %q", st.HoldReason)
	}
	if len(rt.holds) != 1 || rt.lifted(policyIP) {
		t.Fatal("a held sandbox keeps its DROPs")
	}
}

func TestUpdateNetworkPolicyApplyStepFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		from []string
		to   []string
		set  func(*policyRuntime)
	}{
		{"block", nil, []string{"1.1.1.0/24"}, func(r *policyRuntime) { r.blockErr = errors.New("iptables") }},
		{"clear old", []string{"1.1.1.0/24"}, nil, func(r *policyRuntime) { r.clearErr = errors.New("iptables") }},
		{"apply new", nil, []string{"1.1.1.0/24"}, func(r *policyRuntime) { r.applyErr = errors.New("iptables") }},
		{"lift", nil, []string{"1.1.1.0/24"}, func(r *policyRuntime) { r.liftErr = errors.New("iptables") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, _, rt := newPolicyHarness(t)
			seedPolicySandbox(t, svc, models.Sandbox{NetworkAllowOut: tc.from})
			tc.set(rt)
			_, err := svc.UpdateNetworkPolicy(context.Background(), "sb-pol", models.NetworkPolicyRequest{NetworkAllowOut: tc.to})
			if !errors.Is(err, ErrEgressApplyFailedHeld) {
				t.Fatalf("err = %v, want apply_failed_held", err)
			}
		})
	}
}

// TestUpdateNetworkPolicyStoppedAndQuota: a stopped container is only
// stored; a quota-blocked one keeps the shared DROP.
func TestUpdateNetworkPolicyStoppedAndQuota(t *testing.T) {
	svc, gw, rt := newPolicyHarness(t)
	ctx := context.Background()
	seedPolicySandbox(t, svc, models.Sandbox{Status: models.SandboxStatusStopped})
	if _, err := svc.UpdateNetworkPolicy(ctx, "sb-pol", models.NetworkPolicyRequest{NetworkAllowOut: []string{"pypi.org"}}); err != nil {
		t.Fatal(err)
	}
	if rt.blockCalls != 0 || gw.isAttached("sb-pol") {
		t.Fatal("a stopped sandbox must only be stored; Start applies it")
	}

	svc, _, rt = newPolicyHarness(t)
	seedPolicySandbox(t, svc, models.Sandbox{NetworkBytesOutLimit: 10, NetworkBytesOut: 20, NetworkQuotaExceeded: true})
	if _, err := svc.UpdateNetworkPolicy(ctx, "sb-pol", models.NetworkPolicyRequest{NetworkAllowOut: []string{"1.1.1.0/24"}}); err != nil {
		t.Fatal(err)
	}
	if rt.lifted(policyIP) {
		t.Fatal("an over-quota sandbox must keep its egress DROP")
	}
}

func TestUpdateNetworkPolicyRejects(t *testing.T) {
	ctx := context.Background()
	svc, _, rt := newPolicyHarness(t)
	seedPolicySandbox(t, svc, models.Sandbox{})
	seedPolicySandbox(t, svc, models.Sandbox{ID: "sb-fc", Runtime: models.RuntimeFirecracker})
	seedPolicySandbox(t, svc, models.Sandbox{ID: "sb-new", Status: models.SandboxStatusCreating})
	for _, tc := range []struct {
		name string
		id   string
		req  models.NetworkPolicyRequest
		want error
	}{
		{"hostname in deny", "sb-pol", models.NetworkPolicyRequest{NetworkDenyOut: []string{"evil.example"}}, egresspolicy.ErrInvalid},
		{"firecracker", "sb-fc", models.NetworkPolicyRequest{NetworkBlockAll: true}, models.ErrRuntimeNotImplemented},
		{"creating", "sb-new", models.NetworkPolicyRequest{NetworkBlockAll: true}, ErrEgressPolicyBusy},
		{"missing", "sb-none", models.NetworkPolicyRequest{NetworkBlockAll: true}, store.ErrNotFound},
	} {
		if _, err := svc.UpdateNetworkPolicy(ctx, tc.id, tc.req); !errors.Is(err, tc.want) {
			t.Fatalf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}

	svc.egressSelfTest.Store(&egressSelfTest{kick: make(chan struct{}, 1)})
	hostname := models.NetworkPolicyRequest{NetworkAllowOut: []string{"pypi.org"}}
	if _, err := svc.UpdateNetworkPolicy(ctx, "sb-pol", hostname); !errors.Is(err, ErrEgressGatewayUnavailable) {
		t.Fatalf("pending self-test: err = %v", err)
	}
	svc.egressSelfTest.Load().failed.Store(true)
	if _, err := svc.UpdateNetworkPolicy(ctx, "sb-pol", hostname); !errors.Is(err, ErrEgressSelfTestFailed) {
		t.Fatalf("failed self-test: err = %v", err)
	}
	svc.egressSelfTest.Store(nil)
	svc.cfg.EgressFQDNEnabled = false
	if _, err := svc.UpdateNetworkPolicy(ctx, "sb-pol", hostname); !errors.Is(err, ErrEgressGatewayRequired) {
		t.Fatalf("no gateway: err = %v", err)
	}
	cidr := models.NetworkPolicyRequest{NetworkAllowOut: []string{"1.1.1.0/24"}}
	svc.SetEgressOperator(operatorWatcher(t, "version: 1\nceiling: {allow_out: [10.0.0.0/8]}\n"))
	if _, err := svc.UpdateNetworkPolicy(ctx, "sb-pol", cidr); !errors.Is(err, ErrEgressOperatorConfigInvalid) {
		t.Fatalf("invalid operator file: err = %v", err)
	}
	svc.SetEgressOperator(operatorWatcher(t, "version: 1\nceiling: {allow_out: [10.0.0.0/8]}\ndefault_policy: {mode: block_all}\n"))
	if _, err := svc.UpdateNetworkPolicy(ctx, "sb-pol", cidr); !errors.Is(err, egresspolicy.ErrInvalid) {
		t.Fatalf("outside the ceiling: err = %v", err)
	}
	if rt.blockCalls != 0 {
		t.Fatal("a rejected update must not touch the runtime")
	}
}

// failingUpsertCluster fails the strict spec commit.
type failingUpsertCluster struct {
	*specWriteThroughCluster
	err error
}

func (c *failingUpsertCluster) UpsertSpec(context.Context, string, *models.CreateSandboxRequest, cluster.PlacementSecrets) error {
	return c.err
}

// TestUpdateNetworkPolicyClusterCommit covers D10: the spec commit comes
// first and is strict, so a failure changes nothing.
func TestUpdateNetworkPolicyClusterCommit(t *testing.T) {
	ctx := context.Background()
	svc, _, rt := newPolicyHarness(t)
	seedPolicySandbox(t, svc, models.Sandbox{})
	stub := &specWriteThroughCluster{Noop: cluster.NewNoop("self", "http://self", ""), spec: &models.CreateSandboxRequest{Image: "alpine", CPU: 2}}
	svc.AttachCluster(stub)
	if _, err := svc.UpdateNetworkPolicy(ctx, "sb-pol", models.NetworkPolicyRequest{NetworkAllowOut: []string{"1.1.1.0/24"}}); err != nil {
		t.Fatal(err)
	}
	calls := stub.calls()
	if len(calls) != 1 || !slices.Equal(calls[0].NetworkAllowOut, []string{"1.1.1.0/24"}) || calls[0].CPU != 2 {
		t.Fatalf("replicated specs = %+v", calls)
	}

	for _, tc := range []struct {
		err  error
		want error
	}{
		{errors.New("no leader"), ErrEgressSpecCommitFailed},
		{cluster.ErrRecoveryPayloadTooLarge, egresspolicy.ErrInvalid},
	} {
		svc.AttachCluster(&failingUpsertCluster{specWriteThroughCluster: stub, err: tc.err})
		before := rt.blockCalls
		_, err := svc.UpdateNetworkPolicy(ctx, "sb-pol", models.NetworkPolicyRequest{NetworkAllowOut: []string{"8.8.8.0/24"}})
		if !errors.Is(err, tc.want) {
			t.Fatalf("err = %v, want %v", err, tc.want)
		}
		row, _ := svc.store.Get(ctx, "sb-pol")
		if !slices.Equal(row.NetworkAllowOut, []string{"1.1.1.0/24"}) || rt.blockCalls != before {
			t.Fatal("a failed commit must change nothing")
		}
	}
}

// policyMediatorRuntime stands in for the WASM and isolate drivers, which
// keep the policy for the next instantiation themselves.
type policyMediatorRuntime struct {
	*recordingRuntime
	mu      sync.Mutex
	set     map[string][]string
	blocked map[string]bool
	learn   map[string]bool
	rules   map[string][]egresspolicy.RuleSpec
	secrets map[string]map[string]string
	err     error
}

func (m *policyMediatorRuntime) SetEgressPolicy(id string, allow, _ []string, learn bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.set[id] = allow
	m.learn[id] = learn
	return m.err
}

func (m *policyMediatorRuntime) EgressLearned(id string) (egresspolicy.Learned, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return egresspolicy.Learned{}, m.err
	}
	return egresspolicy.Learned{Entries: []egresspolicy.LearnedEntry{{Host: id + ".example"}}}, nil
}

func (m *policyMediatorRuntime) SetNetworkBlocks(id string, _, out bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.blocked[id] = out
}

func (m *policyMediatorRuntime) UpdateEgressPolicy(id string, blockAll bool, allow, _ []string, learn bool, rules []egresspolicy.RuleSpec, secrets map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rules == nil {
		m.rules = map[string][]egresspolicy.RuleSpec{}
	}
	m.rules[id] = rules
	if m.secrets == nil {
		m.secrets = map[string]map[string]string{}
	}
	m.secrets[id] = secrets
	m.set[id] = allow
	m.blocked[id] = blockAll
	m.learn[id] = learn
	return m.err
}

func newMediator() *policyMediatorRuntime {
	return &policyMediatorRuntime{recordingRuntime: &recordingRuntime{}, set: map[string][]string{}, blocked: map[string]bool{}, learn: map[string]bool{}}
}

func TestUpdateNetworkPolicyMediatedRuntimes(t *testing.T) {
	ctx := context.Background()
	svc, _, rt := newPolicyHarness(t)
	wasm, iso := newMediator(), newMediator()
	svc.wasm, svc.isolate = wasm, iso
	seedPolicySandbox(t, svc, models.Sandbox{ID: "sb-wasm", Runtime: models.RuntimeWasm, Status: models.SandboxStatusStopped})
	seedPolicySandbox(t, svc, models.Sandbox{ID: "sb-iso", Runtime: models.RuntimeIsolate})

	// Hostnames need no gateway here: these runtimes filter in their own
	// mediators, and a stopped one still hears about it for its next start.
	svc.cfg.EgressFQDNEnabled = false
	got, err := svc.UpdateNetworkPolicy(ctx, "sb-wasm", models.NetworkPolicyRequest{NetworkAllowOut: []string{"pypi.org"}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(wasm.set["sb-wasm"], []string{"pypi.org"}) || wasm.blocked["sb-wasm"] || got.EgressStatus != "" {
		t.Fatalf("wasm: set=%v blocked=%v status=%q", wasm.set, wasm.blocked, got.EgressStatus)
	}
	if _, err := svc.UpdateNetworkPolicy(ctx, "sb-wasm", models.NetworkPolicyRequest{NetworkBlockAll: true}); err != nil || !wasm.blocked["sb-wasm"] {
		t.Fatalf("wasm block-all: err=%v blocked=%v", err, wasm.blocked)
	}
	if _, err := svc.UpdateNetworkPolicy(ctx, "sb-iso", models.NetworkPolicyRequest{NetworkBlockAll: true}); err != nil || !iso.blocked["sb-iso"] {
		t.Fatalf("isolate block-all: err=%v blocked=%v", err, iso.blocked)
	}
	if rt.blockCalls != 0 {
		t.Fatal("mediated runtimes must not touch container netrules")
	}

	wasm.err, iso.err = errors.New("worker gone"), errors.New("host gone")
	for _, id := range []string{"sb-wasm", "sb-iso"} {
		if _, err := svc.UpdateNetworkPolicy(ctx, id, models.NetworkPolicyRequest{NetworkAllowOut: []string{"1.1.1.0/24"}}); !errors.Is(err, ErrEgressApplyFailedHeld) {
			t.Fatalf("%s: err = %v", id, err)
		}
	}
	svc.wasm, svc.isolate = &recordingRuntime{}, &recordingRuntime{}
	for _, id := range []string{"sb-wasm", "sb-iso"} {
		if _, err := svc.UpdateNetworkPolicy(ctx, id, models.NetworkPolicyRequest{NetworkAllowOut: []string{"8.8.8.0/24"}}); !errors.Is(err, ErrEgressApplyFailedHeld) {
			t.Fatalf("%s without a live setter: err = %v", id, err)
		}
	}
}

func TestEgressPolicyLocksStripe(t *testing.T) {
	var l egressPolicyLocks
	unlock := l.lock("a")
	done := make(chan struct{})
	go func() {
		l.lock("a")()
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("the same sandbox must wait for the lock")
	case <-time.After(20 * time.Millisecond):
	}
	unlock()
	<-done
}
