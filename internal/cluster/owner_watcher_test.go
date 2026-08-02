package cluster

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/raft"
)

// recordingRecreator captures every RecreateSandbox call so a test can assert
// the cluster owner watcher fired with the expected (id, spec, ports) tuple.
type recordingRecreator struct {
	mu        sync.Mutex
	calls     map[string]recordedRecreate
	attempted bool
	err       error
}

type recordedRecreate struct {
	spec    models.CreateSandboxRequest
	secrets PlacementSecrets
	ports   map[int]ExposedPortRoute
}

// legacyRecreator exercises compatibility with implementations that predate
// SandboxRecreateReporter. Production uses the reporting service, but the
// optional interface must never make the original hook stop running.
type legacyRecreator struct {
	calls int
}

func (r *legacyRecreator) RecreateSandbox(context.Context, string, models.CreateSandboxRequest, PlacementSecrets, map[int]ExposedPortRoute) error {
	r.calls++
	return nil
}

func newRecordingRecreator() *recordingRecreator {
	return &recordingRecreator{calls: make(map[string]recordedRecreate), attempted: true}
}

func (r *recordingRecreator) RecreateSandbox(ctx context.Context, id string, spec models.CreateSandboxRequest, secrets PlacementSecrets, ports map[int]ExposedPortRoute) error {
	_, err := r.RecreateSandboxReport(ctx, id, spec, secrets, ports)
	return err
}

func (r *recordingRecreator) RecreateSandboxReport(_ context.Context, id string, spec models.CreateSandboxRequest, secrets PlacementSecrets, ports map[int]ExposedPortRoute) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls[id] = recordedRecreate{spec: spec, secrets: secrets, ports: ports}
	return r.attempted, r.err
}

func (r *recordingRecreator) setOutcome(attempted bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.attempted = attempted
	r.err = err
}

func (r *recordingRecreator) get(id string) (recordedRecreate, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.calls[id]
	return s, ok
}

// TestOwnerWatcherSkipsWithoutSpec verifies a placement with no Spec doesn't
// trigger a recreate call — the recreator can't reconstruct without the spec.
func TestOwnerWatcherSkipsWithoutSpec(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newTestCluster(t, "leader", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)

	rec := newRecordingRecreator()
	c.AttachRecreator(rec)

	// Placement owned by self, but no Spec.
	cmd := command{Op: opPlace, SandboxID: "sb-no-spec", OwnerNodeID: "leader"}
	payload, _ := encodeCommand(cmd)
	if err := c.raft.raft.Apply(payload, 2*time.Second).Error(); err != nil {
		t.Fatalf("raft Apply: %v", err)
	}

	c.recreateOwnedSandboxes(context.Background())
	if _, ok := rec.get("sb-no-spec"); ok {
		t.Fatal("recreator should not have been invoked for placement without spec")
	}
}

// TestOwnerWatcherRecreatesOwnedSandbox is the headline failover test: a
// placement carrying a spec and pointing to self drives the watcher to call
// the recreator with the original ID and replicated spec.
func TestOwnerWatcherRecreatesOwnedSandbox(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newTestCluster(t, "leader", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	seedSelfFailoverCapacity(c)

	rec := newRecordingRecreator()
	c.AttachRecreator(rec)

	spec := failoverRecreateSpec()
	cmd := command{Op: opPlace, SandboxID: "sb-failover", OwnerNodeID: "leader", Spec: spec}
	payload, _ := encodeCommand(cmd)
	if err := c.raft.raft.Apply(payload, 2*time.Second).Error(); err != nil {
		t.Fatalf("raft Apply: %v", err)
	}

	c.recreateOwnedSandboxes(context.Background())
	got, ok := rec.get("sb-failover")
	if !ok {
		t.Fatal("recreator was not invoked for sb-failover")
	}
	if got.spec.Image != "alpine" || got.spec.CPU != 1 || got.spec.MemoryMB != 512 {
		t.Fatalf("recreator received wrong spec: %+v", got)
	}
}

// TestOwnerWatcherRecreatesWasmDurableSandbox verifies durable WASM placements
// with failover opt-in drive the owner watcher to call RecreateSandbox with the
// WASM runtime spec (UC-39 cluster path).
func TestOwnerWatcherRecreatesWasmDurableSandbox(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newTestCluster(t, "leader", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	seedSelfFailoverCapacity(c)

	rec := newRecordingRecreator()
	c.AttachRecreator(rec)

	spec := failoverWasmRecreateSpec()
	cmd := command{Op: opPlace, SandboxID: "sb-wasm-failover", OwnerNodeID: "leader", Spec: spec}
	payload, _ := encodeCommand(cmd)
	if err := c.raft.raft.Apply(payload, 2*time.Second).Error(); err != nil {
		t.Fatalf("raft Apply: %v", err)
	}

	c.recreateOwnedSandboxes(context.Background())
	got, ok := rec.get("sb-wasm-failover")
	if !ok {
		t.Fatal("recreator was not invoked for sb-wasm-failover")
	}
	if got.spec.Runtime != models.RuntimeWasm || got.spec.Durability != models.DurabilityDurable {
		t.Fatalf("recreator received wrong wasm spec: %+v", got.spec)
	}
}

func TestOwnerWatcherSkipsSandboxWithoutFailoverOptIn(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newTestCluster(t, "leader", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)

	rec := newRecordingRecreator()
	c.AttachRecreator(rec)

	spec := &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 512}
	cmd := command{Op: opPlace, SandboxID: "sb-no-ha", OwnerNodeID: "leader", Spec: spec}
	payload, _ := encodeCommand(cmd)
	if err := c.raft.raft.Apply(payload, 2*time.Second).Error(); err != nil {
		t.Fatalf("raft Apply: %v", err)
	}

	c.recreateOwnedSandboxes(context.Background())
	if _, ok := rec.get("sb-no-ha"); ok {
		t.Fatal("recreator was invoked for a sandbox without failover opt-in")
	}
}

// TestOwnerWatcherReplaysExposedPorts verifies a placement carrying both a spec
// and exposed-port intents drives the watcher to hand the recreator a deep-copy
// of those ports. This is the failover signal the new owner needs to re-issue
// ExposePort and restore L4/L7 routing for the sandbox.
func TestOwnerWatcherReplaysExposedPorts(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newTestCluster(t, "leader", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)

	rec := newRecordingRecreator()
	c.AttachRecreator(rec)

	spec := failoverRecreateSpec()
	place := command{Op: opPlace, SandboxID: "sb-with-ports", OwnerNodeID: "leader", Spec: spec}
	payload, _ := encodeCommand(place)
	if err := c.raft.raft.Apply(payload, 2*time.Second).Error(); err != nil {
		t.Fatalf("raft Apply opPlace: %v", err)
	}
	for port, route := range map[int]ExposedPortRoute{5432: {Protocol: "tcp", HostPort: 22432}, 8080: {Protocol: "http"}} {
		add := command{Op: opAddExposedPort, SandboxID: "sb-with-ports", Port: port, Protocol: route.Protocol, HostPort: route.HostPort}
		payload, _ = encodeCommand(add)
		if err := c.raft.raft.Apply(payload, 2*time.Second).Error(); err != nil {
			t.Fatalf("raft Apply opAddExposedPort: %v", err)
		}
	}

	c.recreateOwnedSandboxes(context.Background())
	got, ok := rec.get("sb-with-ports")
	if !ok {
		t.Fatal("recreator was not invoked for sb-with-ports")
	}
	if got.ports[5432].Protocol != "tcp" || got.ports[5432].HostPort != 22432 || got.ports[8080].Protocol != "http" {
		t.Fatalf("recreator received wrong ports: %+v", got.ports)
	}
	// Mutating the recreator's copy must not bleed back into the FSM — the
	// watcher is supposed to deep-copy before handing the map over.
	got.ports[9999] = ExposedPortRoute{Protocol: "tcp"}
	stored, ok := c.fsm.get("sb-with-ports")
	if !ok {
		t.Fatal("placement disappeared from fsm")
	}
	if _, leaked := stored.ExposedPorts[9999]; leaked {
		t.Fatal("watcher handed out a shared ExposedPorts map; mutation leaked into fsm")
	}
}

// TestEvictThenWatcherEndToEnd is the end-to-end pipeline: a placement on a
// dead node carries an opt-in spec; eviction reassigns it to the live leader;
// the next watcher tick recreates it via the mock recreator. This is the
// failover-recreation scenario expressed against a single-node test cluster
// (the leader picks itself as the recreation target via SelectPlacement's
// fallback-to-self).
func TestEvictThenWatcherEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newTestCluster(t, "leader", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	seedSelfFailoverCapacity(c)

	rec := newRecordingRecreator()
	c.AttachRecreator(rec)

	spec := &models.CreateSandboxRequest{
		Image:    "alpine",
		CPU:      0.5,
		MemoryMB: 256,
		Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
	}
	cmd := command{
		Op: opPlace, SandboxID: "sb-e2e", OwnerNodeID: "dead-node", OwnerAPIURL: "http://gone",
		Spec: spec,
	}
	payload, _ := encodeCommand(cmd)
	if err := c.raft.raft.Apply(payload, 2*time.Second).Error(); err != nil {
		t.Fatalf("raft Apply: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c.evictDeadOwner(ctx, "dead-node")

	owner, err := c.OwnerOf("sb-e2e")
	if err != nil || owner.NodeID != "leader" {
		t.Fatalf("post-evict OwnerOf = %+v err=%v, want NodeID=leader", owner, err)
	}

	c.recreateOwnedSandboxes(ctx)
	got, ok := rec.get("sb-e2e")
	if !ok {
		t.Fatal("recreator was not invoked after evict + watcher tick")
	}
	if got.spec.Image != "alpine" {
		t.Fatalf("recreator received wrong spec: %+v", got)
	}
}

func TestSelectRecreationTargetExcludingSkipsNonOwnersAndDrainedNodes(t *testing.T) {
	index := newGossipMemberIndex()
	index.replace([]Member{
		recreateCandidate("ingress-only", config.NodeRoleIngress, 64),
		recreateCandidate("drained-worker", config.NodeRoleWorker, 96),
		recreateCandidate("worker-ok", config.NodeRoleWorker, 32),
	})
	c := &Cluster{
		nodeID: "self",
		apiURL: "http://self",
		fsm:    newPlacementFSM(),
		gossip: &gossipNode{memberIndex: index},
	}
	c.fsm.drainedNodes["drained-worker"] = true

	target, ok := c.selectRecreationTargetExcluding(failoverRecreateSpec(), "self")
	if !ok {
		t.Fatal("expected a recreation target")
	}
	if target.NodeID != "worker-ok" {
		t.Fatalf("target = %+v, want worker-ok", target)
	}
}

func failoverRecreateSpec() *models.CreateSandboxRequest {
	return &models.CreateSandboxRequest{
		Image:    "alpine",
		CPU:      1,
		MemoryMB: 512,
		Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
	}
}

func failoverWasmRecreateSpec() *models.CreateSandboxRequest {
	return &models.CreateSandboxRequest{
		Runtime:    models.RuntimeWasm,
		Durability: models.DurabilityDurable,
		ModuleRef:  "file:///tmp/demo.wasm",
		CPU:        1,
		MemoryMB:   256,
		Failover:   &models.Failover{Policy: models.FailoverPolicyRecreate},
	}
}

func recreateCandidate(nodeID, role string, freeCPU float64) Member {
	return Member{
		NodeID: nodeID,
		APIURL: "http://" + nodeID,
		Alive:  true,
		Role:   role,
		Capacity: capacity.Snapshot{
			HostCPUCores:      128,
			HostMemoryTotalMB: 65536,
			CPUBudget:         128,
			MemoryBudgetMB:    65536,
			AvailableCPU:      freeCPU,
			AvailableMemoryMB: 65536,
			CanAdmit:          true,
		},
	}
}

// TestFailoverRecreateMetricsMoveOnOwnerDeath is the regression test for the
// failover observability gap: before these counters, a fleet-wide recreate
// storm was visible only as log lines on whichever node happened to pick up
// the placement. Drives a real owner-death → reassign → recreate sequence and
// asserts each counter moves exactly once per event.
func TestFailoverRecreateMetricsMoveOnOwnerDeath(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newTestCluster(t, "leader", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	seedSelfFailoverCapacity(c)

	rec := newRecordingRecreator()
	c.AttachRecreator(rec)

	cmd := command{
		Op: opPlace, SandboxID: "sb-metrics", OwnerNodeID: "dead-node",
		OwnerAPIURL: "http://gone", Spec: failoverRecreateSpec(),
	}
	payload, _ := encodeCommand(cmd)
	if err := c.raft.raft.Apply(payload, 2*time.Second).Error(); err != nil {
		t.Fatalf("raft Apply: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	beforeReassign := clusterFailoverReassignTotal.Value()
	c.evictDeadOwner(ctx, "dead-node")
	if got := clusterFailoverReassignTotal.Value() - beforeReassign; got != 1 {
		t.Fatalf("reassign delta = %d, want 1", got)
	}

	// Successful recreate: attempt counted, no error recorded.
	beforeRecreate := clusterFailoverRecreateTotal.Value()
	beforeErrors := expvarMapValue(clusterFailoverRecreateErrors, "error")
	c.recreateOwnedSandboxes(ctx)
	if got := clusterFailoverRecreateTotal.Value() - beforeRecreate; got != 1 {
		t.Fatalf("recreate delta = %d, want 1", got)
	}
	if got := expvarMapValue(clusterFailoverRecreateErrors, "error") - beforeErrors; got != 0 {
		t.Fatalf("recreate error delta = %d on success, want 0", got)
	}

	// A later watcher pass sees the already-materialized sandbox. The service
	// reports this successful steady-state replay as a no-op, so the metric
	// must stay flat instead of increasing every five seconds forever.
	rec.setOutcome(false, nil)
	beforeRecreate = clusterFailoverRecreateTotal.Value()
	c.recreateOwnedSandboxes(ctx)
	if got := clusterFailoverRecreateTotal.Value() - beforeRecreate; got != 0 {
		t.Fatalf("recreate delta on steady-state no-op = %d, want 0", got)
	}

	// Failing recreate: still one attempt, plus one classified error. This is
	// the counter that feeds the maxRecreateFailuresBeforeReassign escalation.
	// attempted=false is deliberately defensive: any error is an attempt even
	// if a reporter violates the documented outcome contract.
	rec.setOutcome(false, errors.New("docker: no such image"))
	beforeRecreate = clusterFailoverRecreateTotal.Value()
	beforeErrors = expvarMapValue(clusterFailoverRecreateErrors, "error")
	c.recreateOwnedSandboxes(ctx)
	if got := clusterFailoverRecreateTotal.Value() - beforeRecreate; got != 1 {
		t.Fatalf("recreate delta on failure = %d, want 1", got)
	}
	if got := expvarMapValue(clusterFailoverRecreateErrors, "error") - beforeErrors; got != 1 {
		t.Fatalf("recreate error delta = %d, want 1", got)
	}
}

func TestOwnerWatcherFallsBackToLegacyRecreator(t *testing.T) {
	fsm := newPlacementFSM()
	payload, _ := encodeCommand(command{
		Op: opPlace, SandboxID: "sb-legacy-recreator", OwnerNodeID: "self",
		Spec: failoverRecreateSpec(),
	})
	if got := fsm.Apply(&raft.Log{Index: 1, Data: payload}); got != nil {
		t.Fatalf("place: %v", got)
	}

	rec := &legacyRecreator{}
	c := &Cluster{
		nodeID:           "self",
		fsm:              fsm,
		recreator:        rec,
		recreateFailures: &recreateFailureTracker{counts: make(map[string]int)},
	}
	before := clusterFailoverRecreateTotal.Value()
	c.recreateOwnedSandboxes(context.Background())

	if rec.calls != 1 {
		t.Fatalf("legacy recreate calls = %d, want 1", rec.calls)
	}
	if got := clusterFailoverRecreateTotal.Value() - before; got != 1 {
		t.Fatalf("legacy recreate metric delta = %d, want 1", got)
	}
}

// TestFailoverRecreateMetricsStayZeroWithoutOptIn pins the no-op contract: a
// placement that never opted into failover recreate must not move the
// counters, so a fleet running the default policy reads a flat zero.
func TestFailoverRecreateMetricsStayZeroWithoutOptIn(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newTestCluster(t, "leader", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	seedSelfFailoverCapacity(c)

	c.AttachRecreator(newRecordingRecreator())

	// No Failover block — the default "leave it stopped" policy.
	cmd := command{
		Op: opPlace, SandboxID: "sb-no-optin", OwnerNodeID: "dead-node",
		OwnerAPIURL: "http://gone",
		Spec:        &models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 512},
	}
	payload, _ := encodeCommand(cmd)
	if err := c.raft.raft.Apply(payload, 2*time.Second).Error(); err != nil {
		t.Fatalf("raft Apply: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	beforeRecreate := clusterFailoverRecreateTotal.Value()
	beforeReassign := clusterFailoverReassignTotal.Value()
	c.evictDeadOwner(ctx, "dead-node")
	c.recreateOwnedSandboxes(ctx)

	if got := clusterFailoverRecreateTotal.Value() - beforeRecreate; got != 0 {
		t.Errorf("recreate delta = %d without opt-in, want 0", got)
	}
	if got := clusterFailoverReassignTotal.Value() - beforeReassign; got != 0 {
		t.Errorf("reassign delta = %d without opt-in, want 0", got)
	}
}
