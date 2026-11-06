package cluster

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

// A worker (no Raft replica) records, lists, hands over and acks a
// delete_with_sandbox volume reclaim through a server, the path every
// worker's reclaim sweep takes.
func TestAgentVolumeReclaimRoundTripThroughServer(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft/memberlist sockets")
	}
	apiListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("api listen: %v", err)
	}
	server, cleanupServer := newTestClusterWithAPI(t, "srv-agent-rec", true, nil, "http://"+apiListener.Addr().String())
	defer cleanupServer()
	waitForLeader(t, server, 10*time.Second)
	srv := startAgentControlPlaneServerWithVolumes(t, server, apiListener)
	defer srv.Close()
	agent, cleanupAgent := newTestAgentWithRole(t, "wkr-agent-rec", config.NodeRoleWorker,
		[]string{server.gossip.ml.LocalNode().Address()})
	defer cleanupAgent()
	waitForGossipMember(t, server, "wkr-agent-rec", 10*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	deadline := time.Now().Add(10 * time.Second)
	for !agent.VolumeReclaimsReplicated() {
		if time.Now().After(deadline) {
			t.Fatal("the agent never saw every member on this build")
		}
		time.Sleep(50 * time.Millisecond)
	}
	v := models.Volume{ID: "vol-ar", Tenant: "t-a", Name: "scratch", Backend: "s3", Source: "bucket/t-a/scratch", DeleteWithSandbox: true}
	if _, _, err := agent.VolumeUpsert(ctx, v, 0); err != nil {
		t.Fatal(err)
	}
	if err := agent.RecordPlacement(ctx, "sb-ar", nil, PlacementSecrets{IncarnationID: "inc-sb-ar"}); err != nil {
		t.Fatal(err)
	}
	if err := agent.PutVolumeAttachments(ctx, []models.VolumeAttachment{{
		Tenant: "t-a", VolumeID: "vol-ar", SandboxID: "sb-ar", IncarnationID: "inc-sb-ar", Target: "/scratch", Source: v.Source,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := agent.DeletePlacementExact(ctx, "sb-ar", "wkr-agent-rec", "inc-sb-ar"); err != nil {
		t.Fatal(err)
	}
	mine, err := agent.VolumeReclaimsFor(ctx, "wkr-agent-rec", 10)
	if err != nil || len(mine) != 1 || mine[0].VolumeID != "vol-ar" || mine[0].NodeID != "wkr-agent-rec" {
		t.Fatalf("worker's reclaims = %+v, %v", mine, err)
	}
	if err := agent.ClaimVolumeReclaim(ctx, mine[0], ""); err == nil {
		t.Fatal("claim without a node must fail")
	}
	if err := agent.ClaimVolumeReclaim(ctx, mine[0], "wkr-next"); err != nil {
		t.Fatalf("claim: %v", err)
	}
	if err := agent.ClaimVolumeReclaim(ctx, mine[0], "wkr-third"); err == nil {
		t.Fatal("a second claim of the old holder must be refused")
	}
	if left, err := agent.VolumeReclaimsFor(ctx, "wkr-agent-rec", 10); err != nil || len(left) != 0 {
		t.Fatalf("after hand-over the old holder still lists %+v, %v", left, err)
	}
	moved := mine[0]
	moved.NodeID = "wkr-next"
	if err := agent.AckVolumeReclaim(ctx, moved); err != nil {
		t.Fatal(err)
	}
	if all := server.fsm.VolumeReclaims(); len(all) != 0 {
		t.Fatalf("after ack = %+v", all)
	}
}

// An empty ledger reads as an empty list; a worker with no server to ask
// gets an error, so its sweep skips the pass instead of guessing.
func TestAgentVolumeReclaimsForEmptyAndUnreachable(t *testing.T) {
	if _, err := (&Agent{}).VolumeReclaimsFor(context.Background(), "wkr", 1); err == nil {
		t.Fatal("no control plane: want an error")
	}
	if testing.Short() {
		t.Skip("integration test: requires real raft/memberlist sockets")
	}
	apiListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("api listen: %v", err)
	}
	server, cleanupServer := newTestClusterWithAPI(t, "srv-agent-rec2", true, nil, "http://"+apiListener.Addr().String())
	defer cleanupServer()
	waitForLeader(t, server, 10*time.Second)
	srv := startAgentControlPlaneServerWithVolumes(t, server, apiListener)
	defer srv.Close()
	agent, cleanupAgent := newTestAgentWithRole(t, "wkr-agent-rec2", config.NodeRoleWorker,
		[]string{server.gossip.ml.LocalNode().Address()})
	defer cleanupAgent()
	waitForGossipMember(t, server, "wkr-agent-rec2", 10*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, err := agent.VolumeReclaimsFor(ctx, "wkr-agent-rec2", 10)
	if err != nil || got == nil || len(got) != 0 {
		t.Fatalf("empty ledger = %#v, %v", got, err)
	}
}
