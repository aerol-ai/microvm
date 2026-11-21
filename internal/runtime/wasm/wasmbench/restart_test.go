//go:build wasmbench

package wasmbench_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/runtime/wasm"
	"github.com/aerol-ai/microvm/pkg/hostproc"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
)

// (vi) A sandboxd restart, in two processes over one node (BENCH_BASE, a
// folder the caller makes and removes):
//
//   - BENCH_RESTART=before starts the node, creates a first sandbox (the
//     module is compiled) and one for an owner whose resident host stays
//     up, then exits without stopping its workers, as sandboxd does on a
//     restart (they run in a cgroup of their own);
//   - BENCH_RESTART=after starts a new driver over the same folders, takes
//     the running workers over, and times the first create after the
//     restart, a same-bucket one onto the host it took over or a new
//     owner's (BENCH_RESTART_FIRST=same|new), then more of each.
//
// The caller kills what is left in the cgroup (cgroup.kill) after "after".
// Only the files that set up a tree differ between trees, as for the rest
// of the bench.

// restartCgroup is the cgroup, under the cgroup v2 root, the workers run in.
const restartCgroup = "aerolvm-wasmbench"

// benchCgroup is set while TestCreateLatencyRestart runs: drivers built
// then start their workers in it and take its workers over.
var benchCgroup *hostproc.Cgroup

func useBenchCgroup(d *wasm.Driver, sups ...*worker.Supervisor) {
	if benchCgroup == nil {
		return
	}
	for _, s := range sups {
		s.SetCgroup(benchCgroup)
	}
	d.SetWorkerCgroup(benchCgroup)
}

func TestCreateLatencyRestart(t *testing.T) {
	phase, base := os.Getenv("BENCH_RESTART"), os.Getenv("BENCH_BASE")
	if phase == "" || base == "" {
		t.Skip("BENCH_RESTART and BENCH_BASE are unset")
	}
	benchCgroup = hostproc.NewCgroup(nil, "", restartCgroup, "bench workers")
	t.Cleanup(func() { benchCgroup = nil })
	node := newEnv(t, base, filepath.Join(base, "cache"), true)
	if _, ok := benchCgroup.FD(); !ok {
		t.Fatal("no cgroup for the workers: they would not outlive the first process")
	}
	switch phase {
	case "before":
		node.create(t, "seed-owner", "sb-seed")
		node.create(t, "kept-owner", "sb-kept")
		return
	case "after":
	default:
		t.Fatalf("BENCH_RESTART=%q: want before or after", phase)
	}
	start := time.Now()
	report := node.driver.AdoptWorkers(context.Background())
	adopt := time.Since(start)
	if report.ResidentHosts < 2 {
		t.Fatalf("took over %+v: want the two resident hosts", report)
	}
	runs := 10
	if v, err := strconv.Atoi(os.Getenv("BENCH_RUNS")); err == nil && v > 0 {
		runs = v
	}
	first, name := []time.Duration{}, "vi_restart_first_same"
	if os.Getenv("BENCH_RESTART_FIRST") == "new" {
		name = "vi_restart_first_new"
		first = append(first, node.create(t, "first-new-owner", "sb-r-first"))
	} else {
		first = append(first, node.create(t, "kept-owner", "sb-r-first"))
	}
	var same, fresh []time.Duration
	for k := range runs {
		same = append(same, node.create(t, "kept-owner", fmt.Sprintf("sb-r-same-%d", k)))
		fresh = append(fresh, node.create(t, fmt.Sprintf("new-owner-r%d", k), fmt.Sprintf("sb-r-new-%d", k)))
	}
	writeResults(t, []result{
		summarize(name, first),
		summarize("vi_restart_same_bucket", same),
		summarize("vi_restart_new_owner", fresh),
		summarize("vi_restart_takeover", []time.Duration{adopt}),
	})
}
