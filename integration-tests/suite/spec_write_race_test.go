//go:build integration

package suite

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// specRaceRounds is how many resize-then-lifecycle pairs UC-706 makes. A
// build without the fix lost the resize in some of them (the follower read
// races the leader telling followers about the commit), so 20 pairs show it.
const specRaceRounds = 20

// UC-706 — two changes to one sandbox's spec, made back to back, both stick.
//
// A spec write replaces the whole replicated spec, so a writer reads it,
// changes a field and writes all of it. A worker reads it from a random
// server, and a follower can answer before it has applied the worker's
// previous write. So a lifecycle change made right after a resize read the
// old size and wrote it back, and the team was charged for a size the
// sandbox no longer had: less than it uses after a growth, which a quota
// should never allow.
//
// The sandbox is failover=recreate, so its lifecycle change writes the spec
// (other sandboxes skip it, #1173). Each pair runs on the owner's loopback,
// so the lifecycle call goes out within milliseconds of the resize's answer,
// as it would from a client next to the cluster; from the laptop the round
// trip to the region gives a follower time to catch up and hides the race.
// After each pair the team's usage, which the leader counts from the
// replicated spec, must show the new size. A lost resize stays lost until
// the next spec write, so the wait for the usage cannot hide one.
func TestSpecWritesKeepBothChanges(t *testing.T) {
	harness.Require(t, sc, "UC-706")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	c := client(t)
	team := quotaTeam("uc706")
	putQuota(t, ctx, team, sdktypes.TeamQuotaOptions{MaxCPU: 4})
	runner := mintToken(t, "uc706", "runner", team)
	sb, err := createAs(t, ctx, sdkFor(t, runner.Secret), sdktypes.CreateSandboxOptions{
		Name:     harness.UniqueName(sc, t),
		Runtime:  "docker",
		CPU:      1,
		Failover: &sdktypes.Failover{Policy: sdktypes.FailoverPolicyRecreate},
	})
	if err != nil {
		t.Fatalf("create as team %s: %v", team, err)
	}
	waitRunning(t, sb)
	owner := resolvePlacementOwner(t, c, sb.ID)
	node, ok := nodeForClusterID(t, c, identityTargets(t), owner)
	if !ok {
		t.Fatalf("owner %q of %s is not a provisioned node", owner, sb.ID)
	}
	target, ok := harness.SSHTarget(node)
	if !ok {
		t.Skipf("owner %s is not SSH-reachable", node.Name)
	}

	var lost []string
	var resizeLat, lifecycleLat []time.Duration
	for i := range specRaceRounds {
		cpu := 0.5
		if i%2 == 1 {
			cpu = 1
		}
		r, l := resizeThenLifecycleOnNode(t, target, runner.Secret, sb.ID, cpu, time.Duration(60+i)*time.Minute)
		resizeLat, lifecycleLat = append(resizeLat, r), append(lifecycleLat, l)
		if charged, ok := awaitTeamCPU(t, ctx, team, cpu, 5*time.Second); !ok {
			lost = append(lost, fmt.Sprintf("round %d: resized to %g CPU, the team is charged %g", i+1, cpu, charged))
		}
	}
	harness.ReportDetail(t, "%d resize-then-lifecycle pairs on the owner's loopback (%s): %d left the team charged for the old size. "+
		"Resize p50 %s, lifecycle p50 %s p95 %s. %s",
		specRaceRounds, node.Name, len(lost), percentile(resizeLat, 50), percentile(lifecycleLat, 50), percentile(lifecycleLat, 95), strings.Join(lost, "; "))
	if len(lost) > 0 {
		t.Errorf("%d of %d lifecycle changes put back the size from before the resize just made: %s", len(lost), specRaceRounds, strings.Join(lost, "; "))
	}
}

// resizeThenLifecycleOnNode resizes id to cpu and at once sets its idle
// timer, both against sandboxd on the node's loopback, and returns each
// call's time. The token goes in on stdin into a 0600 header file, so it is
// never on a remote command line.
func resizeThenLifecycleOnNode(t *testing.T, target, token, id string, cpu float64, idle time.Duration) (resize, lifecycle time.Duration) {
	t.Helper()
	script := fmt.Sprintf(`set -eu
umask 077
h=$(mktemp)
trap 'rm -f "$h"' EXIT
read -r token
printf 'Authorization: Bearer %%s\n' "$token" > "$h"
base=http://127.0.0.1:21212/v1/sandboxes/%s
curl -sS -o /dev/null -w 'resize %%{http_code} %%{time_total}\n' -X POST -H @"$h" \
  -H 'Content-Type: application/json' --data '{"cpu":%s}' "$base/resize"
curl -sS -o /dev/null -w 'lifecycle %%{http_code} %%{time_total}\n' -X PUT -H @"$h" \
  -H 'Content-Type: application/json' --data '{"stop_if_idle_for":%d}' "$base/lifecycle"`,
		id, strconv.FormatFloat(cpu, 'f', -1, 64), idle.Nanoseconds())
	out, err := harness.SSHRunStdin(t, target, script, token+"\n")
	if err != nil {
		t.Fatalf("resize then lifecycle on %s: %v\n%s", target, err, out)
	}
	times := map[string]time.Duration{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Fields(line)
		if len(f) != 3 {
			continue
		}
		if f[1] != "200" {
			t.Fatalf("%s of %s answered %s, want 200\n%s", f[0], id, f[1], out)
		}
		secs, err := strconv.ParseFloat(f[2], 64)
		if err != nil {
			t.Fatalf("parse curl time %q: %v", f[2], err)
		}
		times[f[0]] = time.Duration(secs * float64(time.Second))
	}
	r, okR := times["resize"]
	l, okL := times["lifecycle"]
	if !okR || !okL {
		t.Fatalf("resize then lifecycle on %s: missing a timed call\n%s", target, out)
	}
	return r, l
}

// awaitTeamCPU waits up to wait for the team's usage to show want CPU and
// returns the last value read. The wait covers a usage read that reached a
// follower a moment behind; it cannot cover a lost write, which stays.
func awaitTeamCPU(t *testing.T, ctx context.Context, team string, want float64, wait time.Duration) (float64, bool) {
	t.Helper()
	deadline := time.Now().Add(wait)
	var last float64
	for {
		q, err := client(t).SDK().GetTeamQuota(ctx, team)
		if err != nil {
			t.Fatalf("GetTeamQuota(%s): %v", team, err)
		}
		if q.Usage != nil {
			last = q.Usage.CPU
			if last == want {
				return last, true
			}
		}
		if time.Now().After(deadline) {
			return last, false
		}
		time.Sleep(250 * time.Millisecond)
	}
}
