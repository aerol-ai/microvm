package safety

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// N1 in the M1 EKS drill (k8s/m1), after live run m1d-3: a warm pool learns
// every image a create misses for and keeps warm slots for it, so the first
// cold busybox create taught both workers' pools busybox. One side's "cold"
// creates then came from the pool, and learned slots refilled beside the
// timed creates. These tests hold the kit's answers: cold creates the pool
// never serves or learns, the pool hit or miss read from the worker's own
// Server-Timing, steady pools before a phase, and a cost check that counts
// only the steps a run does.

// m1Bash runs script with bash and returns its output; a failure fails t.
func m1Bash(t *testing.T, script string) string {
	t.Helper()
	out, err := exec.Command("bash", "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("bash: %v\n%s", err, out)
	}
	return string(out)
}

// A cold create carries LOGNAME in its env, which keeps it off the pool
// (internal/runtime/containerd poolEligible): served by no slot, and no
// miss, so nothing is learned. Warm and burst creates do not.
func TestM1N1ColdCreatesStayOffThePool(t *testing.T) {
	body := shellFunc(t, "m1/n1-bench.sh", "body")
	for _, tc := range []struct {
		phase   string
		wantEnv bool
	}{{"cold", true}, {"warm", false}, {"burst", false}} {
		out := m1Bash(t, "phase="+tc.phase+"\n"+body+"\nbody public.ecr.aws/docker/library/busybox:1.36\n")
		var req map[string]any
		if err := json.Unmarshal([]byte(out), &req); err != nil {
			t.Fatalf("%s: body is not JSON: %v\n%s", tc.phase, err, out)
		}
		env, has := req["env"].(map[string]any)
		if has != tc.wantEnv {
			t.Fatalf("%s: env present %v, want %v: %s", tc.phase, has, tc.wantEnv, out)
		}
		if tc.wantEnv && env["LOGNAME"] != "root" {
			t.Fatalf("%s: env %v, want LOGNAME=root", tc.phase, env)
		}
	}
}

// pool_state splits a worker's running park-* tasks into pinned slots
// (gVisor, the pinned image) and learned ones (any other image or
// runtime); stopped tasks and sandbox containers are not counted.
func TestM1PoolStateSplitsPinnedFromLearned(t *testing.T) {
	fn := shellFunc(t, "m1/m1-eks.sh", "pool_state")
	script := `set -euo pipefail
dry=0; sd=/nonexistent; workers=aerolvm-workers
ALPINE=public.ecr.aws/docker/library/alpine:3.20
# The time limit (m1-lib.sh bounded) would exec the real kubectl; here it
# just runs the stub below.
bounded() { shift; "$@"; }
kubectl() {
  cat <<'OUT'
TASK        PID    STATUS
park-aaa    101    RUNNING
park-bbb    102    RUNNING
park-ccc    103    RUNNING
park-ddd    104    STOPPED
park-eee    105    RUNNING
park-fff    106    RUNNING
sb-123      107    RUNNING
---
CONTAINER   IMAGE                                        RUNTIME
park-aaa    public.ecr.aws/docker/library/alpine:3.20    io.containerd.runsc.v1
park-bbb    public.ecr.aws/docker/library/alpine:3.20    io.containerd.runsc.v1
park-ccc    public.ecr.aws/docker/library/alpine:3.20    io.containerd.runsc.v1
park-ddd    public.ecr.aws/docker/library/alpine:3.20    io.containerd.runsc.v1
park-eee    public.ecr.aws/docker/library/busybox:1.36   io.containerd.runsc.v1
park-fff    public.ecr.aws/docker/library/alpine:3.20    io.containerd.runc.v2
sb-123      public.ecr.aws/docker/library/alpine:3.20    io.containerd.runsc.v1
OUT
}
` + fn + "\npool_state aerolvm-general-a\n"
	if got := strings.TrimSpace(m1Bash(t, script)); got != "3 2" {
		t.Fatalf("pool_state = %q, want \"3 2\" (3 pinned; busybox and runc alpine learned)", got)
	}
}

// pools_ready waits for full pinned slots and nothing learned on every
// worker it names.
func TestM1PoolsReadyNeedsFullAndNothingLearned(t *testing.T) {
	fn := shellFunc(t, "m1/m1-eks.sh", "pools_ready")
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"10 0", "10 0", true},
		{"12 0", "10 0", true},
		{"10 6", "10 0", false}, // m1d-3's split worker: learned busybox
		{"10 0", "9 0", false},  // still refilling
		{"0 0", "10 0", false},
	} {
		script := fmt.Sprintf(`M1_N1_POOL_DEPTH=10
pool_state() { case "$1" in a) echo %q ;; b) echo %q ;; esac; }
%s
if pools_ready a b; then echo ready; else echo wait; fi
`, tc.a, tc.b, fn)
		got := strings.TrimSpace(m1Bash(t, script)) == "ready"
		if got != tc.want {
			t.Errorf("pools_ready with %q and %q = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

// n1Stats runs n1-stats.py on log and returns its output (exit 1, a verdict
// over the budget, is not an error here).
func n1Stats(t *testing.T, log string) string {
	t.Helper()
	needTools(t, "python3")
	f := filepath.Join(t.TempDir(), "bench.log")
	if err := os.WriteFile(f, []byte(log), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("python3", "-I", k8sFile(t, "m1/n1-stats.py"), f).CombinedOutput()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 1 {
			t.Fatalf("n1-stats.py: %v\n%s", err, out)
		}
	}
	return string(out)
}

// warmLog is 30 warm rounds; rounds 4 and 5 miss on the split side. With
// marker, each line carries pool=; without it the lines are m1d-2's form.
func warmLog(marker bool) string {
	var b strings.Builder
	for i := 1; i <= 30; i++ {
		for _, side := range []string{"split", "single"} {
			miss := side == "split" && (i == 4 || i == 5)
			ms, pool := 17.5, "hit"
			if side == "split" {
				ms = 18.0
			}
			if miss {
				ms, pool = 230.0, "miss"
			}
			fmt.Fprintf(&b, "N1 warm %d %s client_ms=30 create_ms=%.1f code=201 id=sb-%d", i, side, ms, i)
			if marker {
				b.WriteString(" pool=" + pool)
			}
			b.WriteString("\n")
		}
	}
	return b.String()
}

// The worker's own word decides a pool miss when the log has it; an older
// log falls back to "either side over 100 ms".
func TestM1N1StatsDropsPoolMisses(t *testing.T) {
	for _, marker := range []bool{true, false} {
		out := n1Stats(t, warmLog(marker))
		if !strings.Contains(out, "2 pool-miss rounds left out") || !strings.Contains(out, "warm   split  n=28") {
			t.Fatalf("marker %v: want 2 rounds left out and 28 kept:\n%s", marker, out)
		}
	}
	// A slow create the worker says came from the pool is kept: the time
	// rule no longer guesses for a log that has the marker.
	slowHit := strings.Replace(warmLog(true), "N1 warm 9 split client_ms=30 create_ms=18.0", "N1 warm 9 split client_ms=30 create_ms=140.0", 1)
	if out := n1Stats(t, slowHit); !strings.Contains(out, "2 pool-miss rounds left out") {
		t.Fatalf("a slow hit was left out as a miss:\n%s", out)
	}
	// pool=none on every line (no create asked the pool) says nothing
	// about misses: the time rule decides, as for an older log.
	none := strings.ReplaceAll(warmLog(false), "\n", " pool=none\n")
	if out := n1Stats(t, none); !strings.Contains(out, "2 pool-miss rounds left out") {
		t.Fatalf("pool=none log:\n%s", out)
	}
}

// A warm phase whose pool missed on every round (or all but one) on one
// side has no usable pairs. It must fail the run and say why; it used to
// print no warm line at all and exit 0, so N1 passed with no warm result.
func TestM1N1StatsFailsWhenAPhaseHasNoUsablePairs(t *testing.T) {
	needTools(t, "python3")
	var cold strings.Builder
	for i := 1; i <= 30; i++ {
		fmt.Fprintf(&cold, "N1 cold %d split client_ms=200 create_ms=140.0 code=201 id=sb-c%d pool=none\n", i, i)
		fmt.Fprintf(&cold, "N1 cold %d single client_ms=200 create_ms=139.5 code=201 id=sb-d%d pool=none\n", i, i)
	}
	warm := func(hits int) string {
		var b strings.Builder
		for i := 1; i <= 240; i++ {
			pool := "miss"
			if i <= hits {
				pool = "hit"
			}
			fmt.Fprintf(&b, "N1 warm %d split client_ms=30 create_ms=18.0 code=201 id=sb-w%d pool=%s\n", i, i, pool)
			fmt.Fprintf(&b, "N1 warm %d single client_ms=30 create_ms=17.5 code=201 id=sb-x%d pool=hit\n", i, i)
		}
		return b.String()
	}
	for _, hits := range []int{0, 1} {
		f := filepath.Join(t.TempDir(), "bench.log")
		if err := os.WriteFile(f, []byte(cold.String()+warm(hits)), 0o644); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command("python3", "-I", k8sFile(t, "m1/n1-stats.py"), f).CombinedOutput()
		ee, ok := err.(*exec.ExitError)
		if !ok || ee.ExitCode() != 1 {
			t.Fatalf("%d warm hit(s): want exit 1, got %v\n%s", hits, err, out)
		}
		want := fmt.Sprintf("warm   NO DATA: %d usable pair(s), need 2; %d pool-miss rounds left out", hits, 240-hits)
		if !strings.Contains(string(out), want) {
			t.Fatalf("%d warm hit(s): want %q in:\n%s", hits, want, out)
		}
	}
}

// The running cost check projects only the steps a run does: m1d-3 ran
// N1 alone, and every other step's minutes would have counted against its
// limit.
func TestM1CostProjectionCountsOnlyPlannedSteps(t *testing.T) {
	needTools(t, "python3")
	start := fmt.Sprint(time.Now().Add(-10 * time.Minute).Unix())
	run := func(extra ...string) string {
		args := append([]string{"-I", k8sFile(t, "m1/cost.py"), "--running", "--limit", "100", "--vm-hours", "0",
			"--cell-start", start, "--done", "up,setup"}, extra...)
		out, err := exec.Command("python3", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("cost.py: %v\n%s", err, out)
		}
		return string(out)
	}
	// n1 (15) and down (20) are left of up,setup,n1,down.
	if out := run("--plan", "up,setup,n1,down"); !strings.Contains(out, "with 35 planned min left") {
		t.Fatalf("planned run: %s", out)
	}
	// No plan: every step not done (190 - up 20 - setup 3).
	if out := run(); !strings.Contains(out, "with 167 planned min left") {
		t.Fatalf("whole run: %s", out)
	}
}
