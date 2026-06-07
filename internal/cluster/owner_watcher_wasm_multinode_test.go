package cluster

import (
	"context"
	"testing"
	"time"
)

// TestWasmDurableFailoverMultiNodeClusterSoak exercises durable WASM placement
// failover across a two-node Raft cluster: placement starts on a dead follower,
// eviction reassigns to the live leader, and the owner watcher recreates with spec
// and exposed ports on the new owner.
func TestWasmDurableFailoverMultiNodeClusterSoak(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}

	leader, cleanupLeader := newTestCluster(t, "ldr-wasm-soak", true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 15*time.Second)

	follower, cleanupFollower := newTestCluster(t, "fol-wasm-soak", false, []string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupFollower()
	waitForVoter(t, leader, "fol-wasm-soak", 20*time.Second)

	seedSelfFailoverCapacity(leader)
	seedSelfFailoverCapacity(follower)

	recLeader := newRecordingRecreator()
	recFollower := newRecordingRecreator()
	leader.AttachRecreator(recLeader)
	follower.AttachRecreator(recFollower)

	spec := failoverWasmRecreateSpec()
	const sandboxID = "sb-wasm-multinode"
	place := command{
		Op: opPlace, SandboxID: sandboxID, OwnerNodeID: "fol-wasm-soak",
		OwnerAPIURL: "http://fol-wasm-soak", Spec: spec,
	}
	payload, err := encodeCommand(place)
	if err != nil {
		t.Fatalf("encode opPlace: %v", err)
	}
	if err := leader.raft.raft.Apply(payload, 3*time.Second).Error(); err != nil {
		t.Fatalf("raft Apply opPlace: %v", err)
	}
	for port, route := range map[int]ExposedPortRoute{
		8080: {Protocol: "http"},
		5432: {Protocol: "tcp", HostPort: 25432},
	} {
		add := command{Op: opAddExposedPort, SandboxID: sandboxID, Port: port, Protocol: route.Protocol, HostPort: route.HostPort}
		payload, err = encodeCommand(add)
		if err != nil {
			t.Fatalf("encode opAddExposedPort: %v", err)
		}
		if err := leader.raft.raft.Apply(payload, 3*time.Second).Error(); err != nil {
			t.Fatalf("raft Apply opAddExposedPort: %v", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	leader.evictDeadOwner(ctx, "fol-wasm-soak")

	owner, err := leader.OwnerOf(sandboxID)
	if err != nil {
		t.Fatalf("OwnerOf after evict: %v", err)
	}
	if owner.NodeID != "ldr-wasm-soak" {
		t.Fatalf("post-evict owner = %+v, want ldr-wasm-soak", owner)
	}

	leader.recreateOwnedSandboxes(context.Background())
	got, ok := recLeader.get(sandboxID)
	if !ok {
		t.Fatal("leader recreator was not invoked for sb-wasm-multinode")
	}
	if got.spec.Runtime != spec.Runtime || got.spec.Durability != spec.Durability {
		t.Fatalf("recreator spec = %+v, want wasm durable", got.spec)
	}
	if got.ports[8080].Protocol != "http" || got.ports[5432].HostPort != 25432 {
		t.Fatalf("recreator ports = %+v", got.ports)
	}
	if _, ok := recFollower.get(sandboxID); ok {
		t.Fatal("follower recreator should not run after ownership moved to leader")
	}
}
