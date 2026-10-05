package cluster

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/btree"
)

func TestCoverage97ReservationRetryAndPlacementPage(t *testing.T) {
	fsm := newPlacementFSM()
	expiry := time.Now().Add(2 * time.Minute).Unix()
	ref := testSecretRef("sb-retry", "inc-a")
	base := command{
		Op: opReserve, SandboxID: "sb-retry", OwnerNodeID: "node-a",
		IncarnationID: "inc-a", SecretRef: ref, SecretVersion: 1, SecretSealGeneration: 1,
		ExpiresUnix: expiry,
	}
	if got := applyOp(t, fsm, base); got != nil {
		t.Fatalf("reserve = %v", got)
	}
	changedInc := base
	changedInc.IncarnationID = "inc-b"
	changedInc.SecretRef = testSecretRef("sb-retry", "inc-b")
	if got, ok := applyOp(t, fsm, changedInc).(error); !ok || !strings.Contains(got.Error(), "incarnation") {
		t.Fatalf("incarnation retry = %v", got)
	}
	changedGen := base
	changedGen.SecretSealGeneration = 2
	if got, ok := applyOp(t, fsm, changedGen).(error); !ok || !strings.Contains(got.Error(), "secret handle") {
		t.Fatalf("generation retry = %v", got)
	}
	refreshed := base
	refreshed.SecretRecipients = []string{"node-a", "node-b"}
	refreshed.OwnerRef = "tenant-a"
	refreshed.ExpiresUnix = expiry + 30
	if got := applyOp(t, fsm, refreshed); got != nil {
		t.Fatalf("refresh = %v", got)
	}
	if got := applyOp(t, fsm, command{
		Op: opReserve, SandboxID: "sb-bad", OwnerNodeID: "node-a",
		SecretVersion: 1, ExpiresUnix: expiry,
	}); got == nil {
		t.Fatal("invalid secret handle was reserved")
	}

	bare := &placementFSM{}
	bare.claimOwnerRefLocked("sb-retry", "tenant-a")
	bare.ownerRefIndex = map[string]*btree.BTreeG[string]{"tenant-a": nil}
	bare.releaseOwnerRefLocked("sb-retry", "tenant-a")

	if fsm.placementsForShards(PlacementShardFilter{None: true}) != nil {
		t.Fatal("no-shard filter returned rows")
	}
	if page := fsm.placementPage(PlacementPageRequest{ShardFilter: PlacementShardFilter{None: true}}); !page.Authoritative || len(page.Placements) != 0 {
		t.Fatalf("empty shard page = %+v", page)
	}
	if _, ok := fsm.auditACLForSandbox("", "", time.Now().Unix()); ok {
		t.Fatal("empty sandbox id returned an ACL")
	}
	recordPlacementAuditNode(nil, "node-a")

	fsm.mu.Lock()
	fsm.reservedIndex["ghost"] = struct{}{}
	fsm.mu.Unlock()
	_ = fsm.expiredReservationIDs(time.Now().Unix())

	var sameShard []string
	target := -1
	for i := 0; len(sameShard) < 4 && i < 200000; i++ {
		id := fmt.Sprintf("pg-%d", i)
		shard := PlacementShardForSandbox(id, DefaultPlacementShardCount)
		if target < 0 {
			target = shard
		}
		if shard == target {
			sameShard = append(sameShard, id)
		}
	}
	if len(sameShard) < 4 {
		t.Fatalf("could not find three ids in shard %d", target)
	}
	for _, id := range sameShard {
		if got := applyOp(t, fsm, command{
			Op: opReserve, SandboxID: id, OwnerNodeID: "node-a", ExpiresUnix: expiry,
		}); got != nil {
			t.Fatalf("reserve %s = %v", id, got)
		}
	}
	_ = fsm.placementPage(PlacementPageRequest{
		Limit: 1, PageToken: sameShard[0],
		ShardFilter: PlacementShardFilter{ShardCount: DefaultPlacementShardCount, Shards: []int{target}},
	})

	fsm.mu.Lock()
	placed := fsm.placements[sameShard[0]]
	placed.State = PlacementStatePlaced
	fsm.placements[sameShard[0]] = placed
	_ = fsm.pagePlacementIDsByOwnerRefLocked(
		PlacementPageRequest{Limit: 10, PageToken: "sb-retry"},
		"tenant-a", PlacementShardFilter{}, false, map[int]struct{}{},
	)
	_ = fsm.pagePlacementIDsFromTreeLocked(
		PlacementPageRequest{Limit: 5},
		PlacementShardFilter{ShardCount: DefaultPlacementShardCount},
		false, map[int]struct{}{},
	)
	if fsm.ownerIndex == nil {
		fsm.ownerIndex = map[string]*btree.BTreeG[string]{}
	}
	fsm.ownerIndex["node-a"] = newPlacementIDIndex()
	fsm.ownerIndex["node-a"].ReplaceOrInsert(sameShard[0])
	_ = fsm.pagePlacementIDsByOwnerNodeLocked(
		PlacementPageRequest{Limit: 5}, "node-a", PlacementShardFilter{}, false, nil,
	)
	want := map[int]struct{}{target: {}}
	_ = fsm.pagePlacementIDsLocked(
		PlacementPageRequest{Limit: 1, PageToken: sameShard[0]},
		PlacementShardFilter{ShardCount: DefaultPlacementShardCount, Shards: []int{target}},
		false, want,
	)
	fsm.ownerIndex = nil
	fsm.mu.Unlock()
	otherShard := target + 1
	if otherShard >= DefaultPlacementShardCount {
		otherShard = 0
	}
	_ = fsm.placementPage(PlacementPageRequest{
		Limit: 1, OwnerNodeID: "node-a",
		ShardFilter: PlacementShardFilter{ShardCount: DefaultPlacementShardCount, Shards: []int{otherShard}},
	})

	snapFSM := newPlacementFSM()
	snapFSM.artifactCatalog = map[string]*artifactCatalogKindState{"template": nil}
	if _, err := snapFSM.Snapshot(); err != nil {
		t.Fatal(err)
	}
}
