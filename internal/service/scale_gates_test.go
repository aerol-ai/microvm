package service

import (
	"fmt"
	"os"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
)

func requireServiceScaleGates(t *testing.T) {
	t.Helper()
	if os.Getenv("AEROLVM_SCALE_GATES") != "1" {
		t.Skip("set AEROLVM_SCALE_GATES=1 to run large scale gates")
	}
}

func TestScaleGateIngressShardAssignmentAt10KMembers(t *testing.T) {
	requireServiceScaleGates(t)
	const members = 10_000
	known := make([]cluster.Member, 0, members)
	for i := 0; i < members; i++ {
		known = append(known, cluster.Member{
			NodeID: fmt.Sprintf("ing-%05d", i),
			Role:   config.NodeRoleIngress,
			Alive:  true,
			APIURL: fmt.Sprintf("http://10.1.%d.%d:21212", (i/256)%256, i%256),
		})
	}
	stub := &stubIngressCluster{Noop: cluster.NewNoop("ing-05000", "http://self"), members: known}
	filter := clusterIngressShardFilter(stub, "ing-05000")
	if filter.ShardCount != cluster.DefaultPlacementShardCount {
		t.Fatalf("shard count=%d, want %d", filter.ShardCount, cluster.DefaultPlacementShardCount)
	}
	if len(filter.Shards) == 0 {
		t.Fatal("10k ingress member assignment gave this node zero shards")
	}
	if len(filter.Shards) > 3 {
		t.Fatalf("10k ingress member assignment too wide: got %d shards", len(filter.Shards))
	}
}

func TestScaleGateIngressDeltaAt100KPlacements(t *testing.T) {
	requireServiceScaleGates(t)
	const placements = 100_000
	svc := &Service{
		cfg: config.Config{
			EnableCluster: true,
			Domain:        "",
		},
	}
	view := makeScalePlacements(placements)
	desired, needL4 := svc.buildClusterIngressIntents(view, "self")
	if !needL4 {
		t.Fatal("scale view with raw TCP ports did not request L4 bootstrap")
	}
	if len(desired) != placements*3 {
		t.Fatalf("desired route intents=%d, want %d", len(desired), placements*3)
	}
	ops, commit := svc.planClusterIngressDelta(desired)
	if len(ops) != len(desired) {
		t.Fatalf("initial delta ops=%d, want %d", len(ops), len(desired))
	}
	commit()

	view[placements/2].Version++
	desired, _ = svc.buildClusterIngressIntents(view, "self")
	ops, _ = svc.planClusterIngressDelta(desired)
	if len(ops) > 3 {
		t.Fatalf("one placement mutation produced %d route ops, want <=3", len(ops))
	}
}
