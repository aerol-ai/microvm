package cluster

import (
	"io"
	"log/slog"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestSelectRecreationTargetExcludingFilters(t *testing.T) {
	fat := step3FatCapacity()
	index := newGossipMemberIndex()
	index.upsert(Member{NodeID: "self", Alive: true, Role: config.NodeRoleWorker, APIURL: "http://self", Capacity: fat})
	index.upsert(Member{NodeID: "dead", Alive: false, Role: config.NodeRoleWorker, APIURL: "http://d", Capacity: fat})
	index.upsert(Member{NodeID: "ingress", Alive: true, Role: config.NodeRoleIngress, APIURL: "http://i", Capacity: fat})
	index.upsert(Member{NodeID: "drained", Alive: true, Role: config.NodeRoleWorker, APIURL: "http://dr", Capacity: fat})
	index.upsert(Member{NodeID: "no-url", Alive: true, Role: config.NodeRoleWorker, Capacity: fat})
	index.upsert(Member{NodeID: "peer", Alive: true, Role: config.NodeRoleWorker, APIURL: "http://peer", Capacity: fat})

	fsm := newPlacementFSM()
	applyOp(t, fsm, command{Op: opSetNodeDrainState, NodeID: "drained", Drained: true})
	c := &Cluster{
		nodeID: "self",
		apiURL: "http://self",
		fsm:    fsm,
		gossip: &gossipNode{memberIndex: index},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	target, ok := c.selectRecreationTargetExcluding(&models.CreateSandboxRequest{CPU: 1, MemoryMB: 64}, "self")
	if !ok || target.NodeID != "peer" {
		t.Fatalf("target=%+v ok=%v", target, ok)
	}
	// Only self fits after excluding peer → IsSelf.
	index.replace([]Member{
		{NodeID: "self", Alive: true, Role: config.NodeRoleWorker, APIURL: "http://self", Capacity: fat},
		{NodeID: "tiny", Alive: true, Role: config.NodeRoleWorker, APIURL: "http://t", Capacity: capacity.Snapshot{HostCPUCores: 1, CanAdmit: false, Reasons: []string{"full"}}},
	})
	target, ok = c.selectRecreationTargetExcluding(&models.CreateSandboxRequest{CPU: 1, MemoryMB: 64})
	if !ok || !target.IsSelf {
		t.Fatalf("self target=%+v ok=%v", target, ok)
	}
}
