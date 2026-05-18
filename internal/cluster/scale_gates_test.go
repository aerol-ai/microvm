package cluster

import (
	"fmt"
	"os"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/raft"
)

func requireScaleGates(t *testing.T) {
	t.Helper()
	if os.Getenv("AEROLVM_SCALE_GATES") != "1" {
		t.Skip("set AEROLVM_SCALE_GATES=1 to run large scale gates")
	}
}

func TestScaleGatePlacementPageAndShardAt100K(t *testing.T) {
	requireScaleGates(t)
	fsm := newPlacementFSM()
	const n = 100_000
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("gate-%06d", i)
		place, _ := encodeCommand(command{
			Op:          opPlace,
			SandboxID:   id,
			OwnerNodeID: fmt.Sprintf("node-%04d", i%10_000),
			OwnerAPIURL: fmt.Sprintf("http://10.%d.%d.%d:21212", (i/65536)%256, (i/256)%256, i%256),
			Spec:        &models.CreateSandboxRequest{Image: "alpine"},
		})
		if got := fsm.Apply(&raft.Log{Index: uint64(i + 1), Data: place}); got != nil {
			t.Fatalf("place %d: %v", i, got)
		}
	}

	page := fsm.placementPage(PlacementPageRequest{Limit: 1000})
	if len(page.Placements) != 1000 || page.NextPageToken == "" {
		t.Fatalf("first page len=%d next=%q, want 1000 and next token", len(page.Placements), page.NextPageToken)
	}
	next := fsm.placementPage(PlacementPageRequest{Limit: 1000, PageToken: page.NextPageToken})
	if len(next.Placements) != 1000 || next.Placements[0].SandboxID <= page.Placements[len(page.Placements)-1].SandboxID {
		t.Fatalf("second page did not advance: first=%q prev_last=%q", next.Placements[0].SandboxID, page.Placements[len(page.Placements)-1].SandboxID)
	}

	filter := PlacementShardFilter{ShardCount: DefaultPlacementShardCount, Shards: []int{17, 2048, 8191}}
	shardPage := fsm.placementPage(PlacementPageRequest{Limit: 5000, ShardFilter: filter})
	if len(shardPage.Placements) == 0 {
		t.Fatal("shard page returned no placements")
	}
	for _, p := range shardPage.Placements {
		shard := PlacementShardForSandbox(p.SandboxID, DefaultPlacementShardCount)
		if shard != 17 && shard != 2048 && shard != 8191 {
			t.Fatalf("placement %s returned for wrong shard %d", p.SandboxID, shard)
		}
	}
}

func TestScaleGateHostPortIndexAt100K(t *testing.T) {
	requireScaleGates(t)
	fsm := newPlacementFSM()
	const n = 100_000
	fillFSMWithPlacements(t, fsm, n)

	place, _ := encodeCommand(command{
		Op:          opPlace,
		SandboxID:   "gate-target",
		OwnerNodeID: "node-target",
		Spec:        &models.CreateSandboxRequest{Image: "alpine"},
	})
	if got := fsm.Apply(&raft.Log{Index: 2*n + 1, Data: place}); got != nil {
		t.Fatalf("place target: %v", got)
	}
	add, _ := encodeCommand(command{
		Op:        opAddExposedPort,
		SandboxID: "gate-target",
		Port:      5432,
		Protocol:  models.ExposedPortProtocolTCP,
		HostPort:  40000 + n/2,
	})
	if got := fsm.Apply(&raft.Log{Index: 2*n + 2, Data: add}); got == nil {
		t.Fatal("duplicate host port at 100k placements succeeded")
	}
}
