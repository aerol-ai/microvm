//go:build integration

package suite

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// e2bKeepAliveCalls is how many E2B setTimeout calls each sandbox gets: enough
// that a stray background Raft entry moves the per-call figure by 0.01.
const e2bKeepAliveCalls = 100

// UC-704 — an E2B keep-alive (setTimeout) costs no Raft write on a default
// sandbox, and on a failover=recreate sandbox (the only kind whose replicated
// lifecycle a failover recreate reads back) about one a minute: the first
// call, then one whenever the replicated deadline falls a minute behind.
// Before #1172 every call made two (the lifecycle, then a re-save of the E2B
// facade state that held nothing new), and before the lag one on a failover
// sandbox, so a fleet of keep-alives competed with creates for the leader's
// commit pipeline.
//
// The Raft count is aerolvm_raft_apply_total summed over every server: each
// log entry is applied through the leader, forwarded or not, so the sum is
// the cluster's entry count whichever server leads. A quiet window of the
// same length first measures background entries, which are subtracted. The
// calls are made on the owner node's loopback, so their latency is the
// server-side cost (local SQLite plus any round trips to the servers), not
// the laptop's round trip to the region.
func TestE2BKeepAliveRaftCost(t *testing.T) {
	harness.Require(t, sc, "UC-704")
	targets := identityTargets(t)
	c := client(t)

	var serverBases []string
	for _, n := range targets.Nodes {
		if n.Role != "server" && n.Role != "mixed" {
			continue
		}
		if _, ok := harness.SSHTarget(n); !ok {
			continue
		}
		serverBases = append(serverBases, nodeBase(t, n))
	}
	if len(serverBases) == 0 {
		t.Skip("no SSH-reachable server node to read Raft counters from")
	}
	raftEntries := func() float64 {
		var sum float64
		for _, base := range serverBases {
			sum += harness.MetricValueOrZero(nodeMetrics(t, base), "aerolvm_raft_apply_total", nil)
		}
		return sum
	}

	// A default sandbox through the E2B facade, and a failover=recreate one
	// through /v1 (E2B's create has no failover field); the E2B routes serve both.
	defaultID := e2bRunningSandbox(t)
	// Created the way UC-58b does: only the replicated spec's failover policy
	// matters here, not failover_ready (sealed-secret backups, which only the
	// secrets scenarios set up).
	ha := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name:     harness.UniqueName(sc, t),
		Runtime:  "docker",
		Failover: &sdktypes.Failover{Policy: sdktypes.FailoverPolicyRecreate},
	})
	waitRunning(t, ha)

	// Background entries over a quiet window as long as one keep-alive run.
	quiet := 20 * time.Second
	q0 := raftEntries()
	time.Sleep(quiet)
	backgroundPerSecond := (raftEntries() - q0) / quiet.Seconds()

	measure := func(label, id string) (perCall float64, lat []time.Duration, elapsed time.Duration) {
		t.Helper()
		owner := resolvePlacementOwner(t, c, id)
		node, ok := nodeForClusterID(t, c, targets, owner)
		if !ok {
			t.Fatalf("%s: owner %q of %s is not a provisioned node", label, owner, id)
		}
		target, ok := harness.SSHTarget(node)
		if !ok {
			t.Skipf("%s: owner %s is not SSH-reachable", label, node.Name)
		}
		before := raftEntries()
		start := time.Now()
		lat = keepAliveOnNode(t, target, id, e2bKeepAliveCalls)
		elapsed = time.Since(start)
		entries := raftEntries() - before - backgroundPerSecond*elapsed.Seconds()
		return entries / float64(e2bKeepAliveCalls), lat, elapsed
	}

	defaultPerCall, defaultLat, _ := measure("default sandbox", defaultID)
	haPerCall, haLat, haElapsed := measure("failover=recreate sandbox", ha.ID)
	haEntries := haPerCall * e2bKeepAliveCalls

	harness.ReportDetail(t, "%d E2B setTimeout calls each, on the owner's loopback, %d servers counted, background %.2f entries/s. "+
		"Default sandbox: %.2f Raft entries per call, latency p50 %s p95 %s max %s. "+
		"Failover=recreate sandbox: %.1f Raft entries in %s (%.2f per call), latency p50 %s p95 %s max %s.",
		e2bKeepAliveCalls, len(serverBases), backgroundPerSecond,
		defaultPerCall, percentile(defaultLat, 50), percentile(defaultLat, 95), percentile(defaultLat, 100),
		haEntries, haElapsed.Round(time.Second), haPerCall, percentile(haLat, 50), percentile(haLat, 95), percentile(haLat, 100))

	if defaultPerCall > 0.2 {
		t.Errorf("default sandbox: %.2f Raft entries per setTimeout, want 0 (nothing reads its replicated lifecycle back)", defaultPerCall)
	}
	// The first call replicates the new timer, then about one entry a minute
	// (lifecycleReplicationLag). A write can be followed by one or two more:
	// the next call reads the spec from a random server, and a follower that
	// has not applied the write yet returns the copy from before it. So allow
	// up to 5 per started minute; one per call (before the lag) is 100.
	if maxEntries := 5 * (1 + math.Floor(haElapsed.Minutes())); haEntries < 0.5 || haEntries > maxEntries {
		t.Errorf("failover=recreate sandbox: %.1f Raft entries for %d setTimeout calls in %s, want 1 to %.0f (the first, then about one a minute)",
			haEntries, e2bKeepAliveCalls, haElapsed.Round(time.Second), maxEntries)
	}
}

// e2bRunningSandbox creates a sandbox through the E2B facade and waits until
// it runs. It is destroyed when the test ends.
func e2bRunningSandbox(t *testing.T) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	st, body := fcDo(t, ctx, http.MethodPost, "", "/e2b/sandboxes", map[string]any{"templateID": "base", "timeout": 1800}, nil)
	if st != http.StatusCreated {
		t.Fatalf("E2B create = %d, want 201; body=%s", st, string(body))
	}
	var created struct {
		SandboxID string `json:"sandboxID"`
	}
	fcDecode(t, body, &created)
	if created.SandboxID == "" {
		t.Fatalf("E2B create returned no sandboxID: %s", string(body))
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), time.Minute)
		defer ccancel()
		fcDo(t, cctx, http.MethodDelete, "", "/e2b/sandboxes/"+created.SandboxID, nil, nil)
	})
	for {
		st, body := fcDo(t, ctx, http.MethodGet, "", "/e2b/sandboxes/"+created.SandboxID, nil, nil)
		if st == http.StatusOK {
			var dv struct {
				State string `json:"state"`
			}
			fcDecode(t, body, &dv)
			if dv.State == "running" {
				return created.SandboxID
			}
		}
		if ctx.Err() != nil {
			t.Fatalf("E2B sandbox %s never reached running", created.SandboxID)
		}
		time.Sleep(4 * time.Second)
	}
}

// keepAliveOnNode makes n E2B setTimeout calls for id against sandboxd on the
// node's loopback and returns each call's time. The token goes in on stdin
// into a 0600 header file, so it is never on a remote command line.
func keepAliveOnNode(t *testing.T, target, id string, n int) []time.Duration {
	t.Helper()
	script := fmt.Sprintf(`set -eu
umask 077
h=$(mktemp)
trap 'rm -f "$h"' EXIT
read -r token
printf 'Authorization: Bearer %%s\n' "$token" > "$h"
for _ in $(seq 1 %d); do
  curl -sS -o /dev/null -w '%%{http_code} %%{time_total}\n' -X POST -H @"$h" \
    -H 'Content-Type: application/json' --data '{"timeout":1800}' \
    http://127.0.0.1:21212/e2b/sandboxes/%s/timeout
done`, n, id)
	out, err := harness.SSHRunStdin(t, target, script, sc.PAT+"\n")
	if err != nil {
		t.Fatalf("keep-alive loop on %s: %v\n%s", target, err, out)
	}
	var lat []time.Duration
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		if fields[0] != "204" {
			t.Fatalf("setTimeout on %s answered %s, want 204", id, fields[0])
		}
		secs, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			t.Fatalf("parse curl time %q: %v", fields[1], err)
		}
		lat = append(lat, time.Duration(secs*float64(time.Second)))
	}
	if len(lat) != n {
		t.Fatalf("keep-alive loop on %s: %d timed calls, want %d\n%s", target, len(lat), n, out)
	}
	return lat
}
