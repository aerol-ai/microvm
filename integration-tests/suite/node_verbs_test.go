//go:build integration

package suite

// kubectl-style node verbs, Phase 1 (plans/kubectl-style-cluster-ops.md §9,
// UC-610..613). These leave the fleet as they found it; the any-role delete,
// which a node cannot come back from in Phase 1, is zz_node_delete_test.go
// and runs last.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// nodeView is the slice of a member / node record these cases read.
type nodeView struct {
	NodeID           string   `json:"node_id"`
	Role             string   `json:"role"`
	Alive            bool     `json:"alive"`
	Version          string   `json:"version"`
	Voter            bool     `json:"voter"`
	Leader           bool     `json:"leader"`
	Drained          bool     `json:"drained"`
	SandboxesOwned   int      `json:"sandboxes_owned"`
	SandboxesRunning int      `json:"sandboxes_running"`
	SandboxIDs       []string `json:"sandbox_ids"`
}

func listNodeViews(t *testing.T, c *harness.Client) []nodeView {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var resp struct {
		Members []nodeView `json:"members"`
	}
	if err := c.GetJSON(ctx, "/v1/cluster/members", &resp); err != nil {
		t.Fatalf("GET /v1/cluster/members: %v", err)
	}
	return resp.Members
}

func getNodeView(t *testing.T, c *harness.Client, id string, sandboxes int) nodeView {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var v nodeView
	if err := c.GetJSON(ctx, fmt.Sprintf("/v1/cluster/nodes/%s?sandboxes=%d", id, sandboxes), &v); err != nil {
		t.Fatalf("GET /v1/cluster/nodes/%s: %v", id, err)
	}
	return v
}

// rawStatus sends method path with the scenario's token and returns the
// status and body, for the answers a case asserts on (a 404, a 403).
func rawStatus(t *testing.T, method, path string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, sc.BaseURL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+sc.PAT)
	resp, err := harness.HTTPClient(30 * time.Second).Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, string(b)
}

// workerIDs is every alive worker-role member, in member order.
func workerIDs(t *testing.T, c *harness.Client) []string {
	t.Helper()
	var out []string
	for _, n := range listNodeViews(t, c) {
		if n.Role == "worker" && n.Alive {
			out = append(out, n.NodeID)
		}
	}
	return out
}

// requireWorkers skips unless the scenario has role-separated workers: on an
// all-mixed cluster every node is a Raft server and these cases would test
// RemoveMember, not the worker path.
func requireWorkers(t *testing.T, c *harness.Client, n int) []string {
	t.Helper()
	ids := workerIDs(t, c)
	if len(ids) < n {
		t.Skipf("needs %d alive worker-role nodes, the cluster has %d (%v)", n, len(ids), ids)
	}
	return ids
}

// cordonAllBut cordons every worker except keep through the CLI, so new
// creates must land on keep, and uncordons them at cleanup.
func cordonAllBut(t *testing.T, workers []string, keep string) {
	t.Helper()
	env := tokenEnv(t)
	var others []string
	for _, id := range workers {
		if id != keep {
			others = append(others, id)
		}
	}
	if len(others) == 0 {
		return
	}
	mustCLI(t, env, append([]string{"cordon"}, others...)...)
	t.Cleanup(func() {
		if r := runCLI(t, env, nil, append([]string{"uncordon"}, others...)...); r.code != 0 {
			t.Errorf("RESTORE: uncordon %v = %d: %s", others, r.code, r.stderr)
		}
	})
}

// sandboxesOn creates n sandboxes that the placement puts on nodeID (every
// other worker cordoned) and returns their IDs. They are destroyed at cleanup
// unless a case destroys them first.
func sandboxesOn(t *testing.T, c *harness.Client, workers []string, nodeID string, n int) []string {
	t.Helper()
	cordonAllBut(t, workers, nodeID)
	var ids []string
	for i := 0; i < n; i++ {
		sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: fmt.Sprintf("%s-%d", harness.UniqueName(sc, t), i)})
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		owner, err := c.OwnerNodeID(ctx, sb.ID)
		cancel()
		if err != nil || owner != nodeID {
			t.Fatalf("sandbox %s placed on %q (%v), want %s with every other worker cordoned", sb.ID, owner, err, nodeID)
		}
		ids = append(ids, sb.ID)
	}
	return ids
}

// UC-610 — `aerolvm get nodes` shows every member with its role, build
// version and Raft leader, and matches /v1/cluster/members.
func TestNodeVerbsGetNodes(t *testing.T) {
	harness.Require(t, sc, "UC-610")
	c := client(t)
	members := listNodeViews(t, c)
	if want, set := expectedMembers(); set && len(members) != want {
		t.Fatalf("members = %d, want %d", len(members), want)
	}
	leaders := 0
	for _, m := range members {
		if m.Version == "" {
			t.Errorf("member %s gossips no build version (bv)", m.NodeID)
		}
		if m.Leader {
			leaders++
			if !m.Voter {
				t.Errorf("leader %s is not a voter", m.NodeID)
			}
		}
		if m.Role == "worker" && (m.Voter || m.Leader) {
			t.Errorf("worker %s reads as voter=%v leader=%v", m.NodeID, m.Voter, m.Leader)
		}
	}
	if leaders != 1 {
		t.Fatalf("leaders = %d, want exactly 1: %+v", leaders, members)
	}

	env := tokenEnv(t)
	table := mustCLI(t, env, "get", "nodes", "-o", "wide").stdout
	for _, m := range members {
		if !strings.Contains(table, m.NodeID) || (m.Version != "" && !strings.Contains(table, m.Version)) {
			t.Errorf("get nodes is missing %s (version %q):\n%s", m.NodeID, m.Version, table)
		}
		if m.Leader && !strings.Contains(table, "Ready,Leader") {
			t.Errorf("get nodes shows no Ready,Leader row:\n%s", table)
		}
	}
	var listed struct {
		Nodes []nodeView `json:"nodes"`
	}
	mustCLI(t, env, "get", "nodes", "-o", "json").json(t, &listed)
	if len(listed.Nodes) != len(members) {
		t.Fatalf("get nodes -o json = %d nodes, the API %d", len(listed.Nodes), len(members))
	}
	if r := mustCLI(t, env, "version"); !strings.Contains(r.stdout, "Server Version: ") {
		t.Fatalf("aerolvm version printed no server version: %q", r.stdout)
	}
	if r := mustCLI(t, env, "cluster-info"); !strings.Contains(r.stdout, "Leader: ") {
		t.Fatalf("cluster-info = %q", r.stdout)
	}
	t.Logf("UC-610 PASS: %d members, one leader, every member reports its build", len(members))
}

// UC-611 — a cordoned worker gets no new sandboxes and reads as
// SchedulingDisabled; uncordon brings it back.
func TestNodeVerbsCordonKeepsCreatesOff(t *testing.T) {
	harness.Require(t, sc, "UC-611")
	c := client(t)
	workers := requireWorkers(t, c, 2)
	victim := workers[0]
	env := tokenEnv(t)
	if r := mustCLI(t, env, "cordon", victim); !strings.Contains(r.stdout, "node/"+victim+" cordoned") {
		t.Fatalf("cordon = %q", r.stdout)
	}
	uncordoned := false
	t.Cleanup(func() {
		if !uncordoned {
			runCLI(t, env, nil, "uncordon", victim)
		}
	})
	if r := mustCLI(t, env, "get", "nodes", victim); !strings.Contains(r.stdout, "SchedulingDisabled") {
		t.Fatalf("get nodes after cordon = %q", r.stdout)
	}
	for i := 0; i < 2*len(workers); i++ {
		sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: fmt.Sprintf("%s-%d", harness.UniqueName(sc, t), i)})
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		owner, err := c.OwnerNodeID(ctx, sb.ID)
		cancel()
		if err != nil {
			t.Fatalf("owner of %s: %v", sb.ID, err)
		}
		if owner == victim {
			t.Fatalf("sandbox %s landed on cordoned node %s", sb.ID, victim)
		}
	}
	mustCLI(t, env, "uncordon", victim)
	uncordoned = true
	if v := getNodeView(t, c, victim, 0); v.Drained {
		t.Fatalf("%s still cordoned after uncordon", victim)
	}
	t.Logf("UC-611 PASS: %d creates avoided cordoned %s", 2*len(workers), victim)
}

// UC-612 — GET /v1/cluster/nodes/{id} (and describe node) counts what a
// node owns and runs, and lists its sandbox IDs, without the sandbox index.
func TestNodeVerbsNodeCounts(t *testing.T) {
	harness.Require(t, sc, "UC-612")
	c := client(t)
	workers := requireWorkers(t, c, 1)
	target := workers[len(workers)-1]
	before := getNodeView(t, c, target, 0).SandboxesOwned
	ids := sandboxesOn(t, c, workers, target, 2)
	deadline := time.Now().Add(90 * time.Second)
	var v nodeView
	for time.Now().Before(deadline) {
		v = getNodeView(t, c, target, 1000)
		if v.SandboxesOwned >= before+2 && containsString(v.SandboxIDs, ids[0]) && containsString(v.SandboxIDs, ids[1]) {
			break
		}
		time.Sleep(3 * time.Second)
	}
	if v.SandboxesOwned < before+2 || !containsString(v.SandboxIDs, ids[0]) || !containsString(v.SandboxIDs, ids[1]) {
		t.Fatalf("node %s = %+v, want it to own %v", target, v, ids)
	}
	r := mustCLI(t, tokenEnv(t), "describe", "node", target)
	if !strings.Contains(r.stdout, "Sandboxes owned:") || !strings.Contains(r.stdout, "Role:               worker") {
		t.Fatalf("describe node = %q", r.stdout)
	}
	t.Logf("UC-612 PASS: %s owns %d (running %d) and lists both new sandboxes", target, v.SandboxesOwned, v.SandboxesRunning)
}

// UC-613 — `aerolvm drain --delete-sandboxes` on a worker with live
// sandboxes ends with the node owning none, and those sandboxes are gone.
func TestNodeVerbsDrainDeletesSandboxes(t *testing.T) {
	harness.Require(t, sc, "UC-613")
	c := client(t)
	workers := requireWorkers(t, c, 2)
	victim := workers[1]
	ids := sandboxesOn(t, c, workers, victim, 2)
	env := tokenEnv(t)
	t.Cleanup(func() { runCLI(t, env, nil, "uncordon", victim) })

	var res struct {
		Drained bool     `json:"drained"`
		Deleted []string `json:"deleted"`
	}
	mustCLI(t, env, "drain", victim, "--delete-sandboxes", "--timeout", "5m", "--json").json(t, &res)
	if !res.Drained || !containsString(res.Deleted, ids[0]) || !containsString(res.Deleted, ids[1]) {
		t.Fatalf("drain = %+v, want both %v deleted", res, ids)
	}
	if v := getNodeView(t, c, victim, 1000); v.SandboxesOwned != 0 || !v.Drained {
		t.Fatalf("after drain %s = %+v, want cordoned and owning nothing", victim, v)
	}
	for _, id := range ids {
		if code, body := rawStatus(t, http.MethodGet, "/v1/sandboxes/"+id); code != http.StatusNotFound {
			t.Fatalf("drained sandbox %s = %d %s, want 404", id, code, body)
		}
	}
	t.Logf("UC-613 PASS: drain deleted %v and %s owns nothing", res.Deleted, victim)
}

// decodeNodeDelete reads a delete answer; the CLI prints the server's.
func decodeNodeDelete(t *testing.T, r cliResult) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(r.stdout), &out); err != nil {
		t.Fatalf("delete node --json: %v\n%s", err, r.stdout)
	}
	return out
}
