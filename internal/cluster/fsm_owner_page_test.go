package cluster

import (
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Owner-node placement paging is the read path a worker's reconcile sweep uses
// to enumerate its own rows. Before it existed the sweep pulled the global
// placement map — ~72 MB at 100k sandboxes, past the agent's 16 MiB
// control-plane response cap, so every worker failed into an empty cached view
// and silently reclaimed nothing. These tests pin the three properties the
// sweep depends on: it sees only rows this node owns, it sees all of them
// across pages, and it never reports a row the owner index does not hold.

// seedOwnedPlacements applies n placements round-robined across owners.
func seedOwnedPlacements(t testing.TB, fsm *placementFSM, owners []string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("sb-%06d", i)
		place, _ := encodeCommand(command{
			Op:            opPlace,
			SandboxID:     id,
			OwnerNodeID:   owners[i%len(owners)],
			OwnerAPIURL:   "http://" + owners[i%len(owners)],
			Spec:          &models.CreateSandboxRequest{Image: "img"},
			IncarnationID: "inc-" + id,
		})
		if got := fsm.Apply(&raft.Log{Index: uint64(i + 1), Data: place}); got != nil {
			t.Fatalf("seed place %d: %v", i, got)
		}
	}
}

func TestPlacementPageByOwnerNodeReturnsOnlyThatOwner(t *testing.T) {
	fsm := newPlacementFSM()
	owners := []string{"worker-a", "worker-b", "worker-c"}
	seedOwnedPlacements(t, fsm, owners, 300)

	resp := fsm.placementPage(PlacementPageRequest{OwnerNodeID: "worker-b", Limit: 1000})
	if !resp.Authoritative {
		t.Fatal("owner page should be authoritative")
	}
	if len(resp.Placements) != 100 {
		t.Fatalf("owner page returned %d rows, want 100 of 300", len(resp.Placements))
	}
	for _, p := range resp.Placements {
		if p.OwnerNodeID != "worker-b" {
			t.Fatalf("owner page leaked %s owned by %q", p.SandboxID, p.OwnerNodeID)
		}
	}
	if resp.NextPageToken != "" {
		t.Fatalf("NextPageToken = %q, want empty on a complete page", resp.NextPageToken)
	}
}

func TestPlacementPageByOwnerNodeWalksEveryRowAcrossPages(t *testing.T) {
	fsm := newPlacementFSM()
	seedOwnedPlacements(t, fsm, []string{"worker-a", "worker-b"}, 500)

	seen := map[string]struct{}{}
	token := ""
	for page := 0; page < 100; page++ {
		resp := fsm.placementPage(PlacementPageRequest{OwnerNodeID: "worker-a", Limit: 7, PageToken: token})
		if !resp.Authoritative {
			t.Fatalf("page %d not authoritative", page)
		}
		if len(resp.Placements) > 7 {
			t.Fatalf("page %d returned %d rows, want <= 7", page, len(resp.Placements))
		}
		for _, p := range resp.Placements {
			if p.OwnerNodeID != "worker-a" {
				t.Fatalf("page %d leaked %s owned by %q", page, p.SandboxID, p.OwnerNodeID)
			}
			if _, dup := seen[p.SandboxID]; dup {
				t.Fatalf("page %d repeated %s — a cursor that revisits rows makes the sweep O(n^2)", page, p.SandboxID)
			}
			seen[p.SandboxID] = struct{}{}
		}
		if resp.NextPageToken == "" {
			break
		}
		if resp.NextPageToken == token {
			t.Fatalf("page %d cursor did not advance (%q)", page, token)
		}
		token = resp.NextPageToken
	}
	if len(seen) != 250 {
		t.Fatalf("walked %d rows, want all 250 owned by worker-a", len(seen))
	}
}

// A reserved row is a capacity hold, not a live sandbox, and an orphaned row
// has lost its owner. The reconciler deletes placements whose local row is
// missing, so serving either kind under an owner page would let it retire work
// that is mid-flight or already being failed over.
func TestPlacementPageByOwnerNodeExcludesReservedAndOrphaned(t *testing.T) {
	fsm := newPlacementFSM()
	seedOwnedPlacements(t, fsm, []string{"worker-a"}, 3)

	reserve, _ := encodeCommand(command{
		Op:            opReserve,
		SandboxID:     "sb-reserved",
		OwnerNodeID:   "worker-a",
		OwnerAPIURL:   "http://worker-a",
		IncarnationID: "inc-sb-reserved",
		ExpiresUnix:   time.Now().Add(time.Minute).Unix(),
	})
	if got := fsm.Apply(&raft.Log{Index: 900, Data: reserve}); got != nil {
		t.Fatalf("reserve: %v", got)
	}
	orphan, _ := encodeCommand(command{Op: opOrphanOwner, NodeID: "worker-a"})
	if got := fsm.Apply(&raft.Log{Index: 901, Data: orphan}); got != nil {
		t.Fatalf("orphan: %v", got)
	}

	resp := fsm.placementPage(PlacementPageRequest{OwnerNodeID: "worker-a", Limit: 1000})
	for _, p := range resp.Placements {
		if p.IsReserved() || p.IsOrphaned() {
			t.Fatalf("owner page served %s (reserved=%v orphaned=%v)", p.SandboxID, p.IsReserved(), p.IsOrphaned())
		}
	}
}

// The indexed path and the degraded scan path must agree. A partial restore
// drops the owner index, and if the scan fallback answered with a wider set the
// reconciler would act on rows this node does not own.
func TestPlacementPageByOwnerNodeScanFallbackMatchesIndexedPath(t *testing.T) {
	fsm := newPlacementFSM()
	seedOwnedPlacements(t, fsm, []string{"worker-a", "worker-b"}, 60)

	reserve, _ := encodeCommand(command{
		Op:            opReserve,
		SandboxID:     "sb-held",
		OwnerNodeID:   "worker-a",
		OwnerAPIURL:   "http://worker-a",
		IncarnationID: "inc-sb-held",
		ExpiresUnix:   time.Now().Add(time.Minute).Unix(),
	})
	if got := fsm.Apply(&raft.Log{Index: 800, Data: reserve}); got != nil {
		t.Fatalf("reserve: %v", got)
	}

	indexed := fsm.placementPage(PlacementPageRequest{OwnerNodeID: "worker-a", Limit: 1000})

	fsm.mu.Lock()
	fsm.ownerIndex = nil
	fsm.mu.Unlock()
	scanned := fsm.placementPage(PlacementPageRequest{OwnerNodeID: "worker-a", Limit: 1000})

	if len(indexed.Placements) != len(scanned.Placements) {
		t.Fatalf("scan fallback returned %d rows, indexed returned %d", len(scanned.Placements), len(indexed.Placements))
	}
	for i := range indexed.Placements {
		if indexed.Placements[i].SandboxID != scanned.Placements[i].SandboxID {
			t.Fatalf("row %d: indexed=%s scan=%s", i, indexed.Placements[i].SandboxID, scanned.Placements[i].SandboxID)
		}
	}
}

// The whole point of the owner filter is that a worker's reconcile cost tracks
// what it owns, not the size of the fleet. At the 100k/2k target each worker
// owns ~50 rows; a page must not walk the global table to find them.
func TestPlacementPageByOwnerNodeIsBoundedAtFleetScale(t *testing.T) {
	fsm := newPlacementFSM()
	owners := make([]string, 0, 200)
	for i := 0; i < 200; i++ {
		owners = append(owners, fmt.Sprintf("worker-%03d", i))
	}
	seedOwnedPlacements(t, fsm, owners, 20000)

	resp := fsm.placementPage(PlacementPageRequest{OwnerNodeID: "worker-007", Limit: DefaultPlacementPageLimit})
	if len(resp.Placements) != 100 {
		t.Fatalf("owner page returned %d rows, want the 100 owned by worker-007 out of 20000", len(resp.Placements))
	}
	if resp.NextPageToken != "" {
		t.Fatalf("NextPageToken = %q, want empty", resp.NextPageToken)
	}

	// The unfiltered view is what this replaces: it hands back everything.
	all := fsm.placementPage(PlacementPageRequest{Limit: MaxPlacementPageLimit})
	if len(all.Placements) <= len(resp.Placements) {
		t.Fatalf("unfiltered page returned %d rows; the owner filter is not narrowing anything", len(all.Placements))
	}
}

func TestOwnedPlacementIDsLockedStaysSorted(t *testing.T) {
	fsm := newPlacementFSM()
	seedOwnedPlacements(t, fsm, []string{"worker-a"}, 50)

	fsm.mu.RLock()
	ids := fsm.ownedPlacementIDsLocked("worker-a")
	fsm.mu.RUnlock()

	if len(ids) != 50 {
		t.Fatalf("owned ids = %d, want 50", len(ids))
	}
	for i := 1; i < len(ids); i++ {
		if ids[i-1] >= ids[i] {
			t.Fatalf("owned ids not sorted at %d: %q >= %q", i, ids[i-1], ids[i])
		}
	}
}

// A deleting placement is the durable anchor for a delete whose owner crashed
// mid-finalize: the sweep finds it, sees no local row, and completes the exact
// deletion. Reserved and orphaned rows are excluded from the owner page, so it
// would be easy to drop this one with them — and then the anchor is stranded in
// the FSM forever, which is precisely the vacuum the owner page exists to
// close. opBeginDelete must keep the row in the owner index.
func TestPlacementPageByOwnerNodeKeepsDeletingRows(t *testing.T) {
	fsm := newPlacementFSM()
	seedOwnedPlacements(t, fsm, []string{"worker-a"}, 2)

	begin, _ := encodeCommand(command{
		Op:                     opBeginDelete,
		SandboxID:              "sb-000000",
		ExpectedOwnerNodeID:    "worker-a",
		ExpectedOwnerNodeIDSet: true,
		ExpectedIncarnationID:  "inc-sb-000000",
	})
	if got := fsm.Apply(&raft.Log{Index: 700, Data: begin}); got != nil {
		t.Fatalf("begin delete: %v", got)
	}

	resp := fsm.placementPage(PlacementPageRequest{OwnerNodeID: "worker-a", Limit: 1000})
	var found bool
	for _, p := range resp.Placements {
		if p.SandboxID == "sb-000000" {
			found = true
			if !p.IsDeleting() {
				t.Fatalf("sb-000000 state = %q, want deleting", p.State)
			}
		}
	}
	if !found {
		t.Fatal("owner page dropped the deleting row; its exact-delete anchor would never be reclaimed")
	}
}

// An ingress node asks for its rendezvous-hashed shards; a worker asks for its
// own rows. Combining both filters must intersect them, not pick one — and a
// zero ShardCount must normalize rather than divide by zero.
func TestPlacementPageByOwnerNodeIntersectsShardFilter(t *testing.T) {
	fsm := newPlacementFSM()
	seedOwnedPlacements(t, fsm, []string{"worker-a"}, 200)

	all := fsm.placementPage(PlacementPageRequest{OwnerNodeID: "worker-a", Limit: 1000})
	if len(all.Placements) != 200 {
		t.Fatalf("unsharded owner page = %d rows, want 200", len(all.Placements))
	}

	// Pick the shard the first row lands in and ask for only that one.
	target := PlacementShardForSandbox(all.Placements[0].SandboxID, DefaultPlacementShardCount)
	sharded := fsm.placementPage(PlacementPageRequest{
		OwnerNodeID: "worker-a",
		Limit:       1000,
		ShardFilter: PlacementShardFilter{ShardCount: DefaultPlacementShardCount, Shards: []int{target}},
	})
	if len(sharded.Placements) == 0 {
		t.Fatal("owner+shard page returned nothing; the intersection dropped everything")
	}
	if len(sharded.Placements) >= len(all.Placements) {
		t.Fatalf("owner+shard page = %d rows, want fewer than the %d unsharded", len(sharded.Placements), len(all.Placements))
	}
	for _, p := range sharded.Placements {
		if p.OwnerNodeID != "worker-a" {
			t.Fatalf("%s leaked from another owner", p.SandboxID)
		}
		if got := PlacementShardForSandbox(p.SandboxID, DefaultPlacementShardCount); got != target {
			t.Fatalf("%s is in shard %d, want %d", p.SandboxID, got, target)
		}
	}

	// ShardCount 0 must normalize to the default, not panic or return nothing.
	zeroCount := fsm.placementPage(PlacementPageRequest{
		OwnerNodeID: "worker-a",
		Limit:       1000,
		ShardFilter: PlacementShardFilter{Shards: []int{target}},
	})
	if len(zeroCount.Placements) != len(sharded.Placements) {
		t.Fatalf("zero ShardCount = %d rows, want the same %d as the explicit default", len(zeroCount.Placements), len(sharded.Placements))
	}
}
