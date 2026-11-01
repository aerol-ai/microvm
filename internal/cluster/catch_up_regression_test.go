package cluster

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// Regression for the post-restart false "gone" (UC-337, sb-46779d2f94047af2).
// It uses only APIs that predate the catch-up gate so it runs unchanged
// against the old code, where it fails: a server whose FSM is behind the
// leader (a joining follower here, the extreme case of a restart) answered
// its placement page as authoritative while rows the leader had committed
// were still missing, and every list, reconcile and lookup built on that page
// read "missing" as "absent". The invariant: an authoritative page is never
// short of a placement the leader committed before the follower started.
func TestBehindFollowerNeverServesAShortAuthoritativePlacementView(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft/memberlist sockets")
	}
	leader, cleanupLeader := newTestCluster(t, "behind-leader", true, nil)
	defer cleanupLeader()
	waitForLeader(t, leader, 10*time.Second)

	// More than one 64-entry AppendEntries batch, so the follower's own
	// commit index runs ahead of what it has replayed for a while.
	const n = 150
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	for i := 0; i < n; i++ {
		if err := leader.RecordPlacement(ctx, fmt.Sprintf("sb-behind-%03d", i), nil, PlacementSecrets{}); err != nil {
			t.Fatalf("RecordPlacement: %v", err)
		}
	}

	follower, cleanupFollower := newTestCluster(t, "behind-follower", false, []string{leader.gossip.ml.LocalNode().Address()})
	defer cleanupFollower()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		page := follower.PlacementPage(PlacementPageRequest{Limit: MaxPlacementPageLimit})
		if page.Authoritative {
			if len(page.Placements) < n {
				t.Fatalf("authoritative placement page with %d of %d committed placements: a behind node answered absence it cannot prove", len(page.Placements), n)
			}
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("follower never served an authoritative placement page")
}
