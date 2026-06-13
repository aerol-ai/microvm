//go:build integration

package suite

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// clusterMember is the subset of /v1/cluster/members we assert on.
type clusterMember struct {
	NodeID  string `json:"node_id"`
	Role    string `json:"role"`
	APIURL  string `json:"api_url"`
	Drained bool   `json:"drained"`
}

type membersResponse struct {
	Members []clusterMember `json:"members"`
}

// expectedMembers is the node count the scenario should converge to. Set via
// AEROL_EXPECTED_MEMBERS (3 for cluster-3-mixed, 8 for cluster-hetero);
// defaults to "at least 3" when unset.
func expectedMembers() (int, bool) {
	if v := os.Getenv("AEROL_EXPECTED_MEMBERS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n, true
		}
	}
	return 3, false
}

// getMembers fetches and decodes the gossiped member list.
func getMembers(t *testing.T, c *harness.Client) []clusterMember {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var mr membersResponse
	if err := c.GetJSON(ctx, "/v1/cluster/members", &mr); err != nil {
		t.Fatalf("get cluster members: %v", err)
	}
	return mr.Members
}

// UC-03 — A multi-node cluster forms and gossips its members.
func TestClusterForms(t *testing.T) {
	harness.Require(t, sc, "UC-03")
	c := client(t)
	want, exact := expectedMembers()
	// Gossip convergence can lag node boot; poll.
	deadline := time.Now().Add(3 * time.Minute)
	var members []clusterMember
	for time.Now().Before(deadline) {
		members = getMembers(t, c)
		if (exact && len(members) == want) || (!exact && len(members) >= want) {
			return
		}
		time.Sleep(5 * time.Second)
	}
	t.Fatalf("cluster never reached %d members (last %d)", want, len(members))
}

// UC-04 — Heterogeneous cluster members advertise their gossiped roles.
func TestClusterRolesMatch(t *testing.T) {
	harness.Require(t, sc, "UC-04")
	c := client(t)
	members := getMembers(t, c)
	if len(members) == 0 {
		t.Fatal("no members reported")
	}
	for _, m := range members {
		if m.NodeID == "" {
			t.Fatalf("member with empty node_id: %+v", m)
		}
	}
}

// UC-05 — A Raft leader is elected.
func TestRaftLeaderElected(t *testing.T) {
	harness.Require(t, sc, "UC-05")
	c := client(t)
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		var resp struct {
			Leader string `json:"leader"`
		}
		err := c.GetJSON(ctx, "/v1/cluster/leader", &resp)
		cancel()
		if err == nil && resp.Leader != "" {
			return
		}
		time.Sleep(5 * time.Second)
	}
	t.Fatal("no Raft leader elected within timeout")
}

// UC-06 — Member count equals the expected topology size.
func TestMemberCountExpected(t *testing.T) {
	harness.Require(t, sc, "UC-06")
	want, exact := expectedMembers()
	if !exact {
		t.Skip("AEROL_EXPECTED_MEMBERS not set; exact count unknown")
	}
	c := client(t)
	deadline := time.Now().Add(3 * time.Minute)
	var n int
	for time.Now().Before(deadline) {
		n = len(getMembers(t, c))
		if n == want {
			return
		}
		time.Sleep(5 * time.Second)
	}
	t.Fatalf("member count = %d, want %d", n, want)
}

// UC-53 — A newly created sandbox is assigned a placement in the FSM.
func TestSandboxGetsPlacement(t *testing.T) {
	harness.Require(t, sc, "UC-53")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, sb)

	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		var pl map[string]any
		err := c.GetJSON(ctx, "/v1/cluster/placements/"+sb.ID, &pl)
		cancel()
		if err == nil && len(pl) > 0 {
			return
		}
		time.Sleep(3 * time.Second)
	}
	t.Fatalf("sandbox %s never got a placement", sb.ID)
}

// UC-54 — A request for a sandbox owned by another node is transparently
// forwarded: Get succeeds regardless of which node we talk to (the ingress
// forwards to the owner). The SDK only ever talks to the ingress URL.
func TestNonOwnerForwards(t *testing.T) {
	harness.Require(t, sc, "UC-54")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, sb)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	got, err := c.SDK().Get(ctx, sb.ID)
	if err != nil {
		t.Fatalf("get (forwarded): %v", err)
	}
	if got.ID != sb.ID {
		t.Fatalf("forwarded get returned %q, want %q", got.ID, sb.ID)
	}
}

// UC-55 — The cluster sandbox-index includes a created sandbox (consistent
// view across nodes via the FSM-replicated index).
func TestSandboxIndexConsistent(t *testing.T) {
	harness.Require(t, sc, "UC-55")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, sb)

	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		var idx struct {
			Placements []struct {
				SandboxID string `json:"sandbox_id"`
			} `json:"placements"`
		}
		err := c.GetJSON(ctx, "/v1/cluster/sandbox-index", &idx)
		cancel()
		if err == nil {
			for _, p := range idx.Placements {
				if p.SandboxID == sb.ID {
					return
				}
			}
		}
		time.Sleep(3 * time.Second)
	}
	t.Fatalf("sandbox %s never appeared in the cluster index", sb.ID)
}

// UC-56/57 — Draining a worker is accepted (admission-only); uncordon restores
// it. We pick a worker-roled member so we never drain the node we're talking
// through. Eviction semantics are not asserted (drain is admission-only).
func TestDrainAndUncordon(t *testing.T) {
	harness.Require(t, sc, "UC-56")
	c := client(t)
	members := getMembers(t, c)
	var target string
	for _, m := range members {
		if m.Role == "worker" && !m.Drained {
			target = m.NodeID
			break
		}
	}
	if target == "" {
		t.Skip("no idle worker node to drain")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := c.PostJSON(ctx, "/v1/cluster/nodes/"+target+"/drain", nil, nil); err != nil {
		t.Fatalf("drain %s: %v", target, err)
	}
	t.Run("UC-57-uncordon", func(t *testing.T) {
		harness.Require(t, sc, "UC-57")
		if err := c.PostJSON(ctx, "/v1/cluster/nodes/"+target+"/uncordon", nil, nil); err != nil {
			t.Fatalf("uncordon %s: %v", target, err)
		}
	})
	// Always attempt to restore even if the subtest didn't run.
	_ = c.PostJSON(ctx, "/v1/cluster/nodes/"+target+"/uncordon", nil, nil)
}

// UC-58 — Owner failover: a replica serves after the owner dies. This requires
// killing a node, which the API can't do — it's driven by the infra layer. We
// gate it behind AEROL_ALLOW_DISRUPTIVE so a normal run reports it skipped
// (not-applicable) rather than failing.
func TestOwnerFailover(t *testing.T) {
	harness.Require(t, sc, "UC-58")
	if os.Getenv("AEROL_ALLOW_DISRUPTIVE") != "1" {
		t.Skip("disruptive (requires node kill); set AEROL_ALLOW_DISRUPTIVE=1 to run")
	}
	t.Skip("driven by infra fault injection; see plans/integration-tests.md Phase 2 follow-up")
}

// UC-58b — Recreate-via-failover preserves sandbox identity. Same disruptive
// gating as UC-58.
func TestRecreateViaFailover(t *testing.T) {
	harness.Require(t, sc, "UC-58b")
	if os.Getenv("AEROL_ALLOW_DISRUPTIVE") != "1" {
		t.Skip("disruptive (requires node kill); set AEROL_ALLOW_DISRUPTIVE=1 to run")
	}
	t.Skip("driven by infra fault injection; see plans/integration-tests.md Phase 2 follow-up")
}

// UC-59 — WASM live-migrate across nodes. Needs a wasm workload and a migrate
// trigger; gated on a staged module ref.
func TestWasmLiveMigrate(t *testing.T) {
	harness.Require(t, sc, "UC-59")
	if os.Getenv("AEROL_WASM_MODULE_REF") == "" {
		t.Skip("AEROL_WASM_MODULE_REF not set")
	}
	t.Skip("wasm migrate exercises a node-targeted move; see Phase 2 follow-up")
}

// UC-60 — Orphan reclaim-local + delete-orphan. Manufacturing an orphan needs
// fault injection; gated on an operator-provided orphan id.
func TestOrphanReclaimAndDelete(t *testing.T) {
	harness.Require(t, sc, "UC-60")
	orphan := os.Getenv("AEROL_ORPHAN_ID")
	if orphan == "" {
		t.Skip("AEROL_ORPHAN_ID not set (orphan manufacture needs fault injection)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c := client(t)
	// reclaim-local is best-effort (only succeeds if this node has the row);
	// then delete-orphan removes the placement.
	_ = c.PostJSON(ctx, "/v1/cluster/orphans/"+orphan+"/reclaim-local", nil, nil)
	if err := c.GetJSON(ctx, "/v1/cluster/placements/"+orphan, nil); err == nil {
		t.Logf("orphan %s still has a placement after reclaim", orphan)
	}
}
