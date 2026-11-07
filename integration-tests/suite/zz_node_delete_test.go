//go:build integration

package suite

// The any-role node delete, Phase 1 (plans/kubectl-style-cluster-ops.md §5,
// UC-614/615). Disruptive and permanent for the rest of the run: a deleted
// node ID stays denied until Phase 2's fresh join replaces the record, so
// the worker this deletes does not come back. The file sorts last ("zz_")
// so every other case runs against the full fleet first.

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
)

// pickDeletableWorker is a worker-role, non-seed node this run can SSH to.
func pickDeletableWorker(t *testing.T, targets *harness.IntegrationTargets) harness.IntegrationNode {
	t.Helper()
	for _, n := range targets.Nodes {
		if n.Seed || !strings.EqualFold(strings.TrimSpace(n.Role), "worker") {
			continue
		}
		if _, ok := harness.SSHTarget(n); ok {
			return n
		}
	}
	t.Skip("no SSH-reachable worker-role node to delete (the case needs a role-separated scenario such as cluster-hetero-lite)")
	return harness.IntegrationNode{}
}

// internalCallFrom has node call a Raft server's internal mTLS listener
// with its OWN certificate and token, as its sandboxd does, and returns the
// status and body. It reads the drained set: a route every build serves.
func internalCallFrom(t *testing.T, node, server harness.IntegrationNode) (int, string, error) {
	t.Helper()
	target, ok := harness.SSHTarget(node)
	if !ok {
		return 0, "", fmt.Errorf("node %s has no SSH address", node.Name)
	}
	script := `sudo bash -c 'set -a; . /etc/sandboxd/sandboxd.env 2>/dev/null || true; . /etc/sandboxd/cluster.env; set +a; ` +
		`base="${SB_CLUSTER_INTERNAL_ADVERTISE%/}"; hostport="${base#https://}"; port="${hostport##*:}"; ` +
		`curl -sS -o /tmp/aerolvm-uc615.body -w "\nPROBE_CODE=%{http_code}\n" --max-time 20 ` +
		`--resolve "aerolvm-cluster-node:$port:` + server.PrivateIP + `" ` +
		`-H "Authorization: Bearer $SB_PAT_TOKEN" ` +
		`--cert "$SB_CLUSTER_TLS_DIR/node.crt" --key "$SB_CLUSTER_TLS_DIR/node.key" --cacert "$SB_CLUSTER_TLS_DIR/ca.crt" ` +
		`"https://aerolvm-cluster-node:$port/v1/cluster/internal/drained-nodes"; rc=$?; ` +
		`echo; echo PROBE_BODY_START; head -c 2000 /tmp/aerolvm-uc615.body; echo; echo PROBE_BODY_END; printf "PROBE_RC=%s\n" "$rc"'`
	out, err := harness.SSHRun(t, target, script)
	code := 0
	if i := strings.LastIndex(out, "PROBE_CODE="); i >= 0 {
		fmt.Sscanf(out[i+len("PROBE_CODE="):], "%d", &code)
	}
	body := ""
	if s, e := strings.Index(out, "PROBE_BODY_START"), strings.Index(out, "PROBE_BODY_END"); s >= 0 && e > s {
		body = strings.TrimSpace(out[s+len("PROBE_BODY_START") : e])
	}
	if code == 0 && err == nil {
		err = fmt.Errorf("internal call from %s produced no status: %s", node.Name, out)
	}
	return code, body, err
}

func pickServer(t *testing.T, targets *harness.IntegrationTargets) harness.IntegrationNode {
	t.Helper()
	for _, n := range targets.Nodes {
		if n.Seed {
			return n
		}
	}
	for _, n := range targets.Nodes {
		if strings.EqualFold(n.Role, "server") {
			return n
		}
	}
	t.Skip("no Raft server in the targets")
	return harness.IntegrationNode{}
}

func memberPresent(t *testing.T, c *harness.Client, id string) bool {
	t.Helper()
	for _, m := range listNodeViews(t, c) {
		if m.NodeID == id {
			return true
		}
	}
	return false
}

// UC-614 — `aerolvm delete node` removes a worker (the new DELETE
// /v1/cluster/nodes/{id}): it leaves the member list, a retry succeeds, and
// the soft-frozen DELETE /v1/cluster/members/{id} still answers 404 for a
// worker. UC-615 — the deleted node cannot come back as a peer: its own
// certificate is refused on a server's internal listener, and after a
// sandboxd restart it is still not a member.
func TestNodeDeleteWorkerAndItCannotRejoin(t *testing.T) {
	harness.Require(t, sc, "UC-614", "UC-615")
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled: this deletes a worker for the rest of the run")
	}
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	c := client(t)
	workers := requireWorkers(t, c, 2)
	victim := pickDeletableWorker(t, targets)
	harness.RequireNodeSSH(t, victim)
	victimID := heteroNodeID(t, c, targets, victim.Name)
	if !containsString(workers, victimID) {
		t.Skipf("%s (%s) is not an alive worker member: %v", victim.Name, victimID, workers)
	}
	server := pickServer(t, targets)
	env := tokenEnv(t)

	// Control: before the delete its own certificate is accepted, so a 403
	// afterwards means revocation, not a broken probe.
	if code, body, err := internalCallFrom(t, victim, server); err != nil || code != http.StatusOK {
		t.Fatalf("control internal call from %s before delete = %d %q %v", victim.Name, code, body, err)
	}
	// The old route answers a worker 404 today, and must keep doing so.
	if code, body := rawStatus(t, http.MethodDelete, "/v1/cluster/members/"+victimID); code != http.StatusNotFound {
		t.Fatalf("DELETE /v1/cluster/members/%s before delete = %d %s, want the unchanged 404", victimID, code, body)
	}

	deleted := false
	t.Cleanup(func() {
		if !deleted {
			runCLI(t, env, nil, "uncordon", victimID)
			return
		}
		// Phase 1 has no undelete: stop the denied daemon so it stops
		// knocking, and keep it out of the harness's API pool.
		if target, ok := harness.SSHTarget(victim); ok {
			if out, err := harness.SSHRun(t, target, "sudo systemctl stop sandboxd"); err != nil {
				t.Logf("stop sandboxd on deleted %s: %v\n%s", victim.Name, err, out)
			}
		}
		harness.MarkNodeDown(victim.PublicIP)
		t.Logf("NOTE: %s (%s) was deleted and stays denied; the rest of this run has one worker fewer", victim.Name, victimID)
	})

	// Drain it with a live sandbox on it, then delete it.
	ids := sandboxesOn(t, c, workers, victimID, 1)
	mustCLI(t, env, "drain", victimID, "--delete-sandboxes", "--timeout", "5m")
	if v := getNodeView(t, c, victimID, 10); v.SandboxesOwned != 0 {
		t.Fatalf("after drain %s still owns %d (%v); sandbox %v", victimID, v.SandboxesOwned, v.SandboxIDs, ids)
	}
	res := decodeNodeDelete(t, mustCLI(t, env, "delete", "node", victimID, "--json"))
	deleted = true
	if res["denied"] != true || res["role"] != "worker" {
		t.Fatalf("delete node = %+v, want a denied worker", res)
	}

	t.Run("UC-614-gone-from-members", func(t *testing.T) {
		deadline := time.Now().Add(2 * time.Minute)
		for memberPresent(t, c, victimID) && time.Now().Before(deadline) {
			time.Sleep(5 * time.Second)
		}
		if memberPresent(t, c, victimID) {
			t.Fatalf("deleted %s is still in /v1/cluster/members", victimID)
		}
		if r := mustCLI(t, env, "get", "nodes"); strings.Contains(r.stdout, victimID) {
			t.Fatalf("get nodes still lists %s:\n%s", victimID, r.stdout)
		}
		if code, body := rawStatus(t, http.MethodGet, "/v1/cluster/nodes/"+victimID); code != http.StatusNotFound {
			t.Fatalf("GET /v1/cluster/nodes/%s after delete = %d %s, want 404", victimID, code, body)
		}
		if code, body := rawStatus(t, http.MethodDelete, "/v1/cluster/members/"+victimID); code != http.StatusNotFound {
			t.Fatalf("DELETE /v1/cluster/members/%s after delete = %d %s, want 404", victimID, code, body)
		}
		// A retry is a success, never an error on its own success.
		mustCLI(t, env, "delete", "node", victimID)
		t.Logf("UC-614 PASS: %s deleted, gone from members, old route still 404, retry exit 0", victimID)
	})

	t.Run("UC-615-cannot-rejoin", func(t *testing.T) {
		probe := func(when string) {
			t.Helper()
			deadline := time.Now().Add(2 * time.Minute)
			var code int
			var body string
			var err error
			for time.Now().Before(deadline) {
				code, body, err = internalCallFrom(t, victim, server)
				if err == nil && code == http.StatusForbidden && strings.Contains(body, "was deleted") {
					return
				}
				time.Sleep(5 * time.Second)
			}
			t.Fatalf("%s: internal call from deleted %s = %d %q %v, want 403 \"was deleted\"", when, victim.Name, code, body, err)
		}
		probe("after delete")
		target, _ := harness.SSHTarget(victim)
		if out, err := harness.SSHRun(t, target, "sudo systemctl restart sandboxd"); err != nil {
			t.Fatalf("restart sandboxd on %s: %v\n%s", victim.Name, err, out)
		}
		// Give gossip far longer than a join takes; it must never return.
		end := time.Now().Add(90 * time.Second)
		for time.Now().Before(end) {
			if memberPresent(t, c, victimID) {
				t.Fatalf("deleted %s rejoined the member list after a restart", victimID)
			}
			time.Sleep(10 * time.Second)
		}
		probe("after restart")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if metrics, err := c.GetText(ctx, "/v1/metrics"); err == nil && !strings.Contains(metrics, "aerolvm_deny_hits_total") {
			t.Logf("note: /v1/metrics on the API node shows no aerolvm_deny_hits_total yet (counted on the node that refused)")
		}
		t.Logf("UC-615 PASS: %s's own certificate is refused (403 deleted) and a restart does not bring it back", victim.Name)
	})
}
