package cluster

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// recordingRecreator captures every RecreateSandbox call so a test can assert
// the cluster owner watcher fired with the expected (id, spec, ports) tuple.
type recordingRecreator struct {
	mu    sync.Mutex
	calls map[string]recordedRecreate
	err   error
}

type recordedRecreate struct {
	spec    models.CreateSandboxRequest
	secrets PlacementSecrets
	ports   map[int]ExposedPortRoute
}

func newRecordingRecreator() *recordingRecreator {
	return &recordingRecreator{calls: make(map[string]recordedRecreate)}
}

func (r *recordingRecreator) RecreateSandbox(_ context.Context, id string, spec models.CreateSandboxRequest, secrets PlacementSecrets, ports map[int]ExposedPortRoute) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls[id] = recordedRecreate{spec: spec, secrets: secrets, ports: ports}
	return r.err
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

func failoverRecreateSpec() *models.CreateSandboxRequest {
	return &models.CreateSandboxRequest{
		Image:    "alpine",
		CPU:      1,
		MemoryMB: 512,
		Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
	}
}
