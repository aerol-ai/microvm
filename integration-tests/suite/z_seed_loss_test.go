//go:build integration

package suite

import (
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
)

// Group N, UC-170 — losing the seed.
//
// Every other disruptive case deliberately spares the seed (see
// requireNonSeedVictim). This is the one case that targets it, because the
// seed is where the bug was: the seed runs with SB_CLUSTER_BOOTSTRAP=true and
// no SB_CLUSTER_PEERS, so after a restart it had no way back into gossip.
// The survivors — correctly — elected a leader and, after the dead-owner
// grace, evicted it from Raft; a leader only re-admits a server it can see in
// gossip, so the seed sat as a lone Raft candidate forever while its /health
// still said 200 (live S2 run, 2026-09-26). The fix is the gossip peer cache
// in internal/cluster/gossip_peer_cache.go.

// seedEvictionWait outlasts the default 30s dead-owner grace plus its 5s
// reconcile tick with room to spare. The case must restart the seed AFTER it
// has been evicted: restarting inside the grace would test the easy path, in
// which the seed is still in the Raft configuration and the leader's
// heartbeats reach it regardless of gossip.
const seedEvictionWait = 75 * time.Second

// UC-170 — stop the seed; the survivors keep a leader; restart the seed with
// its configuration untouched; it must rejoin Raft and follow that leader.
func TestSeedLossSurvivorsKeepALeaderAndTheSeedRejoins(t *testing.T) {
	harness.Require(t, sc, "UC-170")
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled (drop --no-disruptive)")
	}
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}

	var seed harness.IntegrationNode
	var survivors []harness.IntegrationNode
	for _, n := range targets.Nodes {
		switch {
		case n.Seed:
			seed = n
		case isControlPlaneRole(n.Role):
			survivors = append(survivors, n)
		}
	}
	if seed.Name == "" {
		t.Fatal("no node is marked seed in the integration targets")
	}
	// Two surviving voters out of three is a quorum. With fewer the cluster
	// is SUPPOSED to lose its leader, and the case would test nothing.
	if len(survivors) < 2 {
		t.Skipf("need at least 2 non-seed control-plane nodes for a surviving quorum, have %d", len(survivors))
	}
	harness.RequireNodeSSH(t, seed)
	seedTarget, _ := harness.SSHTarget(seed)
	observer := survivors[0]
	harness.RequireNodeSSH(t, observer)
	observerTarget, _ := harness.SSHTarget(observer)

	restore := harness.KillNodeDaemon(t, seed)
	t.Cleanup(restore)

	// 1. The survivors elect a leader that is not the seed.
	var leader string
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		leader = nodeLocalLeader(t, observerTarget)
		if leader != "" && !strings.HasSuffix(leader, "-"+seed.Name) && leader != seed.Name {
			break
		}
		leader = ""
		time.Sleep(3 * time.Second)
	}
	if leader == "" {
		t.Fatalf("with the seed %s stopped, %s never saw a leader other than the seed within 90s; 2 of 3 voters is a quorum and must elect", seed.Name, observer.Name)
	}
	t.Logf("UC-170: survivors elected %s with the seed %s down", leader, seed.Name)

	// 2. Stay down past the eviction, so the restart exercises the path that
	// used to strand the seed rather than the one that always worked.
	time.Sleep(seedEvictionWait)

	// 3. Restart with no changes — exactly what systemd does. restore waits
	// for the cluster-wide rejoin (members, leader, fresh capacity).
	restore()

	// 4. The seed itself must follow the cluster's leader. A server that is
	// not in the Raft configuration never receives a heartbeat, so its own
	// view stays empty; the old failure looked exactly like that, forever.
	var seedView string
	deadline = time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		clusterLeader := nodeLocalLeader(t, observerTarget)
		seedView = nodeLocalLeader(t, seedTarget)
		if seedView != "" && seedView == clusterLeader {
			t.Logf("UC-170: restarted seed follows leader %s", seedView)
			return
		}
		time.Sleep(5 * time.Second)
	}
	t.Fatalf("the restarted seed %s never rejoined Raft: its own /v1/cluster/leader is %q (want the survivors' leader); it is a gossip island and a lone candidate — check for 'cluster gossip bootstrap rejoined peers' in its journal", seed.Name, seedView)
}

// nodeLocalLeader asks ONE node, over SSH, who it thinks the leader is. The
// public API cannot answer this: the ingress spreads requests across nodes,
// so it reports whichever node it happened to hit.
func nodeLocalLeader(t *testing.T, target string) string {
	t.Helper()
	out, err := harness.SSHRun(t, target, `sudo bash -c '`+sqliteSourceEnv+
		`curl -s --max-time 5 -H "Authorization: Bearer $SB_PAT_TOKEN" http://127.0.0.1:21212/v1/cluster/leader'`)
	if err != nil {
		return ""
	}
	return harness.ParseLeaderJSON(lastNonEmptyLineSuite(out))
}

func isControlPlaneRole(role string) bool {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "server", "mixed", "":
		return true
	}
	return false
}
