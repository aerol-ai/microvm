package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// Regression tests for placement rules (plans/placement-rules.md): labels
// ride the capacity heartbeat, the rule rides the spec, and placement filters
// on labels before power-of-two-choices.

// labelledWorker is a roomy docker worker carrying labels in its heartbeat.
func labelledWorker(nodeID string, labels map[string]string) Member {
	m := slotWorker(nodeID, 16, []string{models.RuntimeDocker})
	m.Capacity.Labels = labels
	return m
}

func zoneLabels(zone string, extra ...string) map[string]string {
	out := map[string]string{models.PlacementZoneLabel: zone}
	for i := 0; i+1 < len(extra); i += 2 {
		out[extra[i]] = extra[i+1]
	}
	return out
}

func TestSelectPlacementFiltersOnLabelsBeforePowerOfTwo(t *testing.T) {
	c := slotCluster(
		labelledWorker("worker-a", zoneLabels("zone-a")),
		labelledWorker("worker-b", zoneLabels("zone-b", "gpu", "a10")),
		labelledWorker("worker-c", zoneLabels("zone-b")),
		// An unlabelled node is the emptiest, so without the filter
		// power-of-two-choices would pick it often.
		slotWorker("worker-big", 96, []string{models.RuntimeDocker}),
	)
	cases := []struct {
		name  string
		rule  map[string]string
		allow map[string]bool
	}{
		{name: "zone", rule: zoneLabels("zone-b"), allow: map[string]bool{"worker-b": true, "worker-c": true}},
		{name: "zone and label", rule: zoneLabels("zone-b", "gpu", "a10"), allow: map[string]bool{"worker-b": true}},
		{name: "label alone", rule: map[string]string{"gpu": "a10"}, allow: map[string]bool{"worker-b": true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for i := range 60 {
				target, cands, err := c.SelectPlacementWithCandidates(capacity.Request{CPU: 0.5, MemoryMB: 128, Runtime: models.RuntimeDocker, Labels: tc.rule})
				if err != nil {
					t.Fatalf("iter %d: %v", i, err)
				}
				if !tc.allow[target.NodeID] {
					t.Fatalf("iter %d placed on %s, outside the rule %v", i, target.NodeID, tc.rule)
				}
				if !reflect.DeepEqual(candidateIDs(cands), tc.allow) {
					t.Fatalf("candidates %v, want exactly %v (the filter runs before p2c)", candidateIDs(cands), tc.allow)
				}
			}
		})
	}
	// No rule: the unlabelled node is still a candidate, exactly as before.
	_, cands, err := c.SelectPlacementWithCandidates(capacity.Request{CPU: 0.5, MemoryMB: 128, Runtime: models.RuntimeDocker})
	if err != nil || len(cands) != 4 {
		t.Fatalf("no rule: candidates=%d err=%v, want all 4", len(cands), err)
	}
}

func TestSelectPlacementNoLabelMatchIsUnsatisfiable(t *testing.T) {
	c := slotCluster(labelledWorker("worker-a", zoneLabels("zone-a")), labelledWorker("worker-b", zoneLabels("zone-b")))
	before := expvarCount(schedulerCandidateRejects.Get("placement_rule"))
	_, err := c.SelectPlacement(capacity.Request{CPU: 0.5, MemoryMB: 128, Labels: zoneLabels("zone-z", "gpu", "h100")})
	if !errors.Is(err, ErrPlacementUnsatisfiable) {
		t.Fatalf("err = %v, want ErrPlacementUnsatisfiable", err)
	}
	// 409, not the retryable 503: it must not read as "no target yet".
	if errors.Is(err, ErrNoPlacementTarget) {
		t.Fatalf("an unsatisfiable rule must not be an ErrNoPlacementTarget: %v", err)
	}
	if !strings.Contains(err.Error(), "gpu=h100, zone=zone-z") {
		t.Fatalf("message %q does not name the rule", err)
	}
	if after := expvarCount(schedulerCandidateRejects.Get("placement_rule")); after != before+2 {
		t.Fatalf("placement_rule rejects = %d, want %d", after, before+2)
	}
}

// A rule some node satisfies is a capacity question once those nodes are
// busy, stale or drained: retryable, never 409.
func TestSelectPlacementMatchingNodeUnavailableIsNotUnsatisfiable(t *testing.T) {
	full := labelledWorker("worker-full", zoneLabels("zone-a"))
	full.Capacity.ReservedCPU = full.Capacity.CPUBudget
	stale := labelledWorker("worker-stale", zoneLabels("zone-a"))
	stale.CapacityStale = true
	drainedWorker := labelledWorker("worker-drained", zoneLabels("zone-a"))
	other := labelledWorker("worker-other", zoneLabels("zone-b"))

	rule := capacity.Request{CPU: 1, MemoryMB: 128, Labels: zoneLabels("zone-a")}
	if _, err := slotCluster(full, other).SelectPlacement(rule); !errors.Is(err, ErrClusterAtCapacity) {
		t.Fatalf("matching node full = %v, want ErrClusterAtCapacity", err)
	}
	if _, err := slotCluster(stale, other).SelectPlacement(rule); !errors.Is(err, ErrNoPlacementTarget) || errors.Is(err, ErrPlacementUnsatisfiable) {
		t.Fatalf("matching node with a stale heartbeat = %v, want a retryable ErrNoPlacementTarget", err)
	}
	c := slotCluster(drainedWorker, other)
	c.fsm.drainedNodes["worker-drained"] = true
	if _, err := c.SelectPlacement(rule); !errors.Is(err, ErrNoPlacementTarget) || errors.Is(err, ErrPlacementUnsatisfiable) {
		t.Fatalf("matching node drained = %v, want a retryable ErrNoPlacementTarget", err)
	}
}

// Mixed versions: a worker on an older build sends no labels, so it never
// satisfies a rule. A rule fails closed rather than land on it; a create
// without a rule still uses it.
func TestSelectPlacementOldBuildWithoutLabelsFailsClosed(t *testing.T) {
	old := slotWorker("worker-old", 16, []string{models.RuntimeDocker})
	c := slotCluster(old)
	if _, err := c.SelectPlacement(capacity.Request{CPU: 0.5, MemoryMB: 128, Labels: zoneLabels("zone-a")}); !errors.Is(err, ErrPlacementUnsatisfiable) {
		t.Fatalf("rule against an unlabelled old build = %v, want ErrPlacementUnsatisfiable", err)
	}
	target, err := c.SelectPlacement(capacity.Request{CPU: 0.5, MemoryMB: 128})
	if err != nil || target.NodeID != "worker-old" {
		t.Fatalf("no rule must still place on the old build: target=%+v err=%v", target, err)
	}
}

// A node-bound artifact (built image, js bundle) whose node lacks the rule's
// labels can never satisfy both: 409, not the artifact error.
func TestSelectPlacementRequiredNodeOutsideRuleIsUnsatisfiable(t *testing.T) {
	c := slotCluster(labelledWorker("worker-a", zoneLabels("zone-a")), labelledWorker("worker-b", zoneLabels("zone-b")))
	_, err := c.SelectPlacement(capacity.Request{CPU: 0.5, MemoryMB: 128, RequiredNodeID: "worker-a", Labels: zoneLabels("zone-b")})
	if !errors.Is(err, ErrPlacementUnsatisfiable) {
		t.Fatalf("err = %v, want ErrPlacementUnsatisfiable", err)
	}
	_, err = c.SelectPlacement(capacity.Request{CPU: 0.5, MemoryMB: 128, RequiredNodeID: "worker-gone", Labels: zoneLabels("zone-b")})
	if !errors.Is(err, ErrArtifactNodeUnavailable) {
		t.Fatalf("missing artifact node = %v, want ErrArtifactNodeUnavailable", err)
	}
}

func TestCapacityRequestFromSpecCarriesPlacementLabels(t *testing.T) {
	spec := &models.CreateSandboxRequest{Placement: &models.PlacementRule{Zone: "zone-a", Labels: map[string]string{"gpu": "a10"}}}
	if got := capacityRequestFromSpec(spec).Labels; !reflect.DeepEqual(got, zoneLabels("zone-a", "gpu", "a10")) {
		t.Fatalf("Labels = %v", got)
	}
	if got := capacityRequestFromSpec(&models.CreateSandboxRequest{}).Labels; got != nil {
		t.Fatalf("no rule must give no labels, got %v", got)
	}
}

func TestNodeFitsRejectsNodeOutsideRule(t *testing.T) {
	m := labelledWorker("w", zoneLabels("zone-a"))
	if nodeFits(m, capacity.Request{CPU: 1, MemoryMB: 64, Labels: zoneLabels("zone-b")}, capacity.Request{}) {
		t.Fatal("a node outside the rule must never fit")
	}
	if !nodeFits(m, capacity.Request{CPU: 1, MemoryMB: 64, Labels: zoneLabels("zone-a")}, capacity.Request{}) {
		t.Fatal("a node inside the rule must fit")
	}
}

// The leader re-checks the rule: a router on an older build that ignored the
// rule cannot reserve onto a node outside it.
func TestAdmitReservationCommandsRefusesNodeOutsideRule(t *testing.T) {
	members := []Member{labelledWorker("worker-a", zoneLabels("zone-a"))}
	inside := reservationCommand{SandboxID: "sb-in", OwnerNodeID: "worker-a", Spec: &models.CreateSandboxRequest{CPU: 1, MemoryMB: 64, Placement: &models.PlacementRule{Zone: "zone-a"}}}
	outside := reservationCommand{SandboxID: "sb-out", OwnerNodeID: "worker-a", Spec: &models.CreateSandboxRequest{CPU: 1, MemoryMB: 64, Placement: &models.PlacementRule{Zone: "zone-b"}}}
	if err := admitReservationCommands(members, nil, nil, nil, 0, []reservationCommand{inside}); err != nil {
		t.Fatalf("inside the rule: %v", err)
	}
	err := admitReservationCommands(members, nil, nil, nil, 0, []reservationCommand{outside})
	if !errors.Is(err, ErrPlacementUnsatisfiable) {
		t.Fatalf("outside the rule = %v, want ErrPlacementUnsatisfiable", err)
	}
	// And the verdict survives a leader-forward hop as the same sentinel.
	if status := ApplyErrorStatus(err); status != http.StatusConflict {
		t.Fatalf("ApplyErrorStatus = %d, want 409", status)
	}
	if back := forwardApplyStatus(http.StatusConflict, err.Error()); !errors.Is(back, ErrPlacementUnsatisfiable) {
		t.Fatalf("forwarded verdict = %v, want ErrPlacementUnsatisfiable", back)
	}
}

type refusalRecorder struct {
	mu       sync.Mutex
	refusals []FailoverRefusal
}

func (r *refusalRecorder) RecreateSandbox(context.Context, string, models.CreateSandboxRequest, PlacementSecrets, map[int]ExposedPortRoute) error {
	return nil
}

func (r *refusalRecorder) RecordFailoverRefused(f FailoverRefusal) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refusals = append(r.refusals, f)
}

func (r *refusalRecorder) snapshot() []FailoverRefusal {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]FailoverRefusal(nil), r.refusals...)
}

// Failover keeps the rule (P1.5): the recipient-constrained scan and the
// fast SelectPlacement path both skip nodes outside it, and an empty set
// says why.
func TestSelectRecreationTargetRespectsPlacementRule(t *testing.T) {
	index := newGossipMemberIndex()
	index.upsert(labelledWorker("worker-a", zoneLabels("zone-a")))
	index.upsert(labelledWorker("worker-b", zoneLabels("zone-b")))
	c := &Cluster{nodeID: "leader", fsm: newPlacementFSM(), gossip: &gossipNode{memberIndex: index},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	sealed := func(zone string) Placement {
		return Placement{
			SandboxID:            "sb-1",
			Spec:                 &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 128, Placement: &models.PlacementRule{Zone: zone}},
			SecretRef:            "present",
			SecretVersion:        secrets.RefVersion,
			SecretSealGeneration: 1,
			SecretRecipients:     []string{"dead", "worker-a", "worker-b"},
		}
	}
	target, err := c.selectRecreationTargetFor(sealed("zone-b"))
	if err != nil || target.NodeID != "worker-b" {
		t.Fatalf("sealed recipients: target=%+v err=%v, want worker-b", target, err)
	}
	if _, err := c.selectRecreationTargetFor(sealed("zone-z")); !errors.Is(err, ErrPlacementUnsatisfiable) {
		t.Fatalf("sealed, no recipient in the zone = %v, want ErrPlacementUnsatisfiable", err)
	}
	// Excluding the only matching node is a plain "no target", not a rule
	// violation: the rule is satisfiable, just not right now.
	if _, err := c.selectRecreationTargetFor(sealed("zone-b"), "worker-b"); !errors.Is(err, ErrNoReassignTarget) {
		t.Fatalf("matching node excluded = %v, want ErrNoReassignTarget", err)
	}
	secretless := Placement{Spec: &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 128, Placement: &models.PlacementRule{Zone: "zone-a"}}}
	for range 20 {
		if target, ok := c.selectRecreationTarget(secretless); !ok || target.NodeID != "worker-a" {
			t.Fatalf("secretless fast path: target=%+v ok=%v, want worker-a", target, ok)
		}
	}
	secretless.Spec.Placement.Zone = "zone-z"
	if _, err := c.selectRecreationTargetFor(secretless); !errors.Is(err, ErrPlacementUnsatisfiable) {
		t.Fatalf("secretless, no node in the zone = %v, want ErrPlacementUnsatisfiable", err)
	}
}

func TestReportFailoverRefusedCountsAndAudits(t *testing.T) {
	rec := &refusalRecorder{}
	c := &Cluster{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	c.AttachRecreator(rec)
	before := expvarCount(clusterFailoverRefused.Get(FailoverRefusalReasonPlacement))
	p := Placement{SandboxID: "sb-x", IncarnationID: " inc ", OwnerRef: "team:risk",
		Spec: &models.CreateSandboxRequest{Placement: &models.PlacementRule{Zone: "zone-a", Labels: map[string]string{"tier": "pci"}}}}
	c.reportFailoverRefused(p, "node-dead", models.PlacementUnsatisfiableError(p.Spec.Placement.RequiredLabels()))
	if after := expvarCount(clusterFailoverRefused.Get(FailoverRefusalReasonPlacement)); after != before+1 {
		t.Fatalf("counter = %d, want %d", after, before+1)
	}
	got := rec.snapshot()
	want := []FailoverRefusal{{SandboxID: "sb-x", IncarnationID: "inc", OwnerRef: "team:risk", FromNodeID: "node-dead",
		Reason: FailoverRefusalReasonPlacement, Rule: "tier=pci, zone=zone-a"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("audit = %+v, want %+v", got, want)
	}
	// A cause that is not a rule is still counted, under its own reason,
	// and a recreator without the recorder half is simply not called.
	c2 := &Cluster{}
	c2.reportFailoverRefused(Placement{SandboxID: "sb-y"}, "n", errors.New("boom"))
	if expvarCount(clusterFailoverRefused.Get("unknown")) == 0 {
		t.Fatal("unknown cause not counted")
	}
}

// The dead-owner reconciler must orphan, never move, a sandbox whose rule no
// live node satisfies, and say so in the counter and the audit record.
func TestEvictDeadOwnerRefusesFailoverOutsidePlacementRule(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newTestCluster(t, "leader", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	seedSelfFailoverCapacity(c)
	rec := &refusalRecorder{}
	c.AttachRecreator(rec)

	place := func(id, zone string) {
		t.Helper()
		payload, err := encodeCommand(command{
			Op: opPlace, SandboxID: id, OwnerNodeID: "dead-node", OwnerAPIURL: "http://gone",
			IncarnationID: "inc-" + id, OwnerRef: "team:risk",
			Spec: &models.CreateSandboxRequest{
				Image: "alpine", CPU: 0.5, MemoryMB: 256,
				Failover:  &models.Failover{Policy: models.FailoverPolicyRecreate},
				Placement: &models.PlacementRule{Zone: zone},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.raft.raft.Apply(payload, 2*time.Second).Error(); err != nil {
			t.Fatalf("raft Apply: %v", err)
		}
	}
	// The leader is the only live worker and carries no zone label, so a
	// zoned sandbox has nowhere it may go.
	place("sb-zoned", "zone-gone")
	before := expvarCount(clusterFailoverRefused.Get(FailoverRefusalReasonPlacement))
	c.evictDeadOwner(context.Background(), "dead-node")
	if _, err := c.OwnerOf("sb-zoned"); err != ErrOrphaned {
		t.Fatalf("OwnerOf = %v, want ErrOrphaned (not moved outside the rule)", err)
	}
	if after := expvarCount(clusterFailoverRefused.Get(FailoverRefusalReasonPlacement)); after != before+1 {
		t.Fatalf("refused counter = %d, want %d", after, before+1)
	}
	refusals := rec.snapshot()
	if len(refusals) != 1 || refusals[0].SandboxID != "sb-zoned" || refusals[0].FromNodeID != "dead-node" ||
		refusals[0].Rule != "zone=zone-gone" || refusals[0].OwnerRef != "team:risk" {
		t.Fatalf("audit records = %+v", refusals)
	}
}

// Labels reach placement through the heartbeat: a peer's GET /v1/capacity
// body carries them into its lease, and the local lease takes them from the
// admitter.
func TestCapacityHeartbeatCarriesLabels(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(capacity.Snapshot{HostCPUCores: 4, HostMemoryTotalMB: 4096, Labels: zoneLabels("zone-a", "gpu", "a10")})
	}))
	defer srv.Close()
	snap, err := fetchCapacitySnapshot(context.Background(), srv.Client(), srv.URL+"/v1/capacity", "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cache := newCapacityLeaseCache("self", capacity.New(capacity.HostInfo{CPUCores: 2, MemoryTotalMB: 2048, Labels: zoneLabels("zone-self")}, capacity.Limits{}, nil), 5*time.Second, nil)
	cache.set("peer", snap, now)
	got := cache.apply([]Member{
		{NodeID: "peer", Alive: true, Role: config.NodeRoleWorker},
		{NodeID: "self", Alive: true, Role: config.NodeRoleWorker},
	}, now)
	if got[0].Capacity.Labels["gpu"] != "a10" || got[0].Capacity.Labels["zone"] != "zone-a" {
		t.Fatalf("peer lease labels = %v", got[0].Capacity.Labels)
	}
	if got[1].Capacity.Labels["zone"] != "zone-self" {
		t.Fatalf("local lease labels = %v", got[1].Capacity.Labels)
	}
}

func TestSelectPlacementErrorResponseCarriesPlacementUnsatisfiable(t *testing.T) {
	resp := SelectPlacementErrorResponse(models.PlacementUnsatisfiableError(zoneLabels("zone-a")))
	if !resp.PlacementUnsatisfiable || !resp.LabelsChecked || !strings.Contains(resp.Error, "zone=zone-a") {
		t.Fatalf("resp = %+v", resp)
	}
}

func TestAgentSelectPlacementPlacementRules(t *testing.T) {
	cases := []struct {
		name    string
		resp    SelectPlacementResponse
		labels  map[string]string
		wantErr error
	}{
		{name: "unsatisfiable verdict keeps its sentinel", labels: zoneLabels("zone-a"),
			resp: SelectPlacementErrorResponse(models.PlacementUnsatisfiableError(zoneLabels("zone-a"))), wantErr: ErrPlacementUnsatisfiable},
		// An older server ignores the labels and answers a target without
		// saying it checked them: the agent must not trust that target.
		{name: "old control plane fails closed", labels: zoneLabels("zone-a"),
			resp: SelectPlacementResponse{Target: PlacementTarget{NodeID: "worker-x"}}, wantErr: ErrPlacementRulesUnsupported},
		{name: "current control plane", labels: zoneLabels("zone-a"),
			resp: SelectPlacementResponse{Target: PlacementTarget{NodeID: "worker-x"}, LabelsChecked: true}},
		{name: "no rule never needs the flag",
			resp: SelectPlacementResponse{Target: PlacementTarget{NodeID: "worker-x"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			capture := &agentControlPlaneCapture{}
			agent := newAgentControlPlaneHarness(t, capture.handler(t, func(w http.ResponseWriter, r *http.Request) bool {
				if r.Method != http.MethodPost || r.URL.Path != PublicInternalSelectPlacementPath {
					return false
				}
				var req SelectPlacementRequest
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Fatalf("decode: %v", err)
				}
				capture.appendSelectRequest(req)
				_ = json.NewEncoder(w).Encode(tc.resp)
				return true
			}), Member{NodeID: "worker-self", Alive: true, Role: config.NodeRoleWorker})
			target, err := agent.SelectPlacement(capacity.Request{CPU: 1, Labels: tc.labels})
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil || target.NodeID != "worker-x" {
				t.Fatalf("target=%+v err=%v", target, err)
			}
			if reqs := capture.selectRequestsSnapshot(); len(reqs) != 1 || !reflect.DeepEqual(reqs[0].Request.Labels, tc.labels) {
				t.Fatalf("the rule must reach the control plane: %+v", reqs)
			}
		})
	}
	if !errors.Is(ErrPlacementRulesUnsupported, ErrNoPlacementTarget) {
		t.Fatal("an old control plane must read as a retryable no-target")
	}
}
