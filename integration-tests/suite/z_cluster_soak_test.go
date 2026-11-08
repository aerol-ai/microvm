//go:build integration

package suite

// UC-482, the soak driver (plans/cluster-phase-2.md §5.3). The node script,
// its parser and the pass rule are in harness/soak.go, unit-tested offline;
// this file only drives the load and takes the samples.
//
// It runs on the focused cluster-chaos scenario, after the fault cases (the
// file sorts after z_cluster_chaos_test.go), as a short smoke run. The long
// run is the same case with a longer AEROL_SOAK_MINUTES and
// AEROL_SUITE_TIMEOUT.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	"github.com/aerol-ai/microvm/pkg/models"
)

// UC-482 — AEROL_SOAK_WORKERS closed-loop workers (default 4) each create a
// sandbox, wait for it to start, run a command in it and delete it, again
// and again for AEROL_SOAK_MINUTES (default 15). Every
// AEROL_SOAK_SAMPLE_SECONDS (default 60) every node is sampled
// (harness.SoakNodeScript, plus aerolvm_go_goroutines and
// aerolvm_ingress_routes_total from its /v1/metrics) along with the
// cluster's placement count; each sample is one JSON line in AEROL_SOAK_OUT
// (default <reports>/<scenario>-soak.jsonl).
//
// I6: after the drain and one reconcile interval, every count (tasks,
// containers, Active snapshots, netns slots, host ports, rows, routes,
// placements) is back at its pre-soak value. The growth rule
// (harness.SoakVerdict): for goroutines, RSS, fds, WAL and Raft size, the
// median of the last third of the load samples is within a margin of the
// first third's. No sandboxd restarts, and at most 1% of cycles (at least
// two) may fail: with no fault injected, errors are themselves a finding.
func TestClusterChaosSoak(t *testing.T) {
	harness.Require(t, sc, "UC-482")
	requireDisruptive(t, "this runs a long closed-loop create and delete load on the fault fleet")
	tp := chaosTopology(t)
	inv := harness.TrackInvariants(t, "I6")
	tag := chaosTag(t)
	observer := chaosAPI(t, tp.servers[0])
	api := operatorAPI()
	reconcile := chaosReconcileInterval(t, tp.workers[0])
	runFor := time.Duration(envInt("AEROL_SOAK_MINUTES", 15)) * time.Minute
	workers := envInt("AEROL_SOAK_WORKERS", 4)
	every := chaosSeconds("AEROL_SOAK_SAMPLE_SECONDS", 60)
	cpu, mem := chaosSmallSize()

	outPath := soakOutPath()
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		t.Fatalf("soak output dir: %v", err)
	}
	outFile, err := os.Create(outPath)
	if err != nil {
		t.Fatalf("soak output: %v", err)
	}
	defer outFile.Close()
	t.Logf("soak samples go to %s", outPath)

	// One tunnel per node for its /v1/metrics, opened once: the samples
	// must not pay an SSH handshake each.
	metrics := map[string]*harness.APIClient{}
	for _, n := range tp.all() {
		metrics[n.Name] = chaosAPI(t, n)
	}
	var cycles, failures atomic.Int64
	var outMu sync.Mutex
	take := func(phase string) harness.SoakSample {
		s := soakSample(t, tp, metrics, observer, phase)
		s.Cycles, s.Errors = cycles.Load(), failures.Load()
		line, _ := json.Marshal(s)
		outMu.Lock()
		defer outMu.Unlock()
		if _, err := outFile.Write(append(line, '\n')); err != nil {
			t.Errorf("write soak sample: %v", err)
		}
		return s
	}

	baseline := take("baseline")
	for name, n := range baseline.Nodes {
		if n.Error != "" {
			t.Fatalf("baseline reading of %s failed, so nothing after it could be compared: %s", name, n.Error)
		}
	}

	prefix := fmt.Sprintf("soak482-%d-", time.Now().Unix())
	deadline := time.Now().Add(runFor)
	var (
		errMu     sync.Mutex
		firstErrs []string
	)
	fail := func(format string, args ...any) {
		failures.Add(1)
		errMu.Lock()
		if len(firstErrs) < 5 {
			firstErrs = append(firstErrs, fmt.Sprintf(format, args...))
		}
		errMu.Unlock()
	}
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; time.Now().Before(deadline); i++ {
				soakCycle(api, chaosRequest(fmt.Sprintf("%s%02d-%05d", prefix, w, i), tag, false, cpu, mem, "", nil), fail)
				cycles.Add(1)
			}
		}(w)
	}

	var load []harness.SoakSample
	stopSampling := make(chan struct{})
	samplerDone := make(chan struct{})
	go func() {
		defer close(samplerDone)
		tick := time.NewTicker(every)
		defer tick.Stop()
		for {
			select {
			case <-stopSampling:
				return
			case <-tick.C:
				load = append(load, take("load"))
			}
		}
	}()
	wg.Wait()
	close(stopSampling)
	<-samplerDone
	t.Logf("%d cycles by %d workers in %s, %d failed", cycles.Load(), workers, runFor, failures.Load())

	// Drain: the workers delete what they made; anything a failed delete
	// left goes now, so the settled sample measures the daemon, not us.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	gone, derr := client(t).SDK().DestroyAll(ctx, map[string]string{"chaos-run": tag})
	cancel()
	if derr != nil {
		t.Errorf("drain: %v (%d deleted)", derr, len(gone))
	} else if len(gone) > 0 {
		t.Logf("drain deleted %d sandboxes a failed cycle left", len(gone))
	}
	// One reconcile interval is the plan's bound; the 30 s is for the
	// ingress's route batch and the census to catch up with it.
	settleFor := reconcile + 30*time.Second
	t.Logf("waiting %s (one reconcile interval) after the drain", settleFor.Round(time.Second))
	time.Sleep(settleFor)
	settled := take("settled")

	verdict := harness.SoakVerdict(baseline, load, settled)
	for _, g := range verdict.Growth {
		t.Logf("growth %s", g)
	}
	for _, n := range verdict.Notes {
		t.Logf("note: %s", n)
	}
	for _, p := range verdict.Problems {
		t.Errorf("soak: %s", p)
	}
	if allowed := max(2, cycles.Load()/100); failures.Load() > allowed {
		t.Errorf("%d of %d cycles failed (allowed %d); first: %s", failures.Load(), cycles.Load(), allowed, strings.Join(firstErrs, "; "))
	} else if failures.Load() > 0 {
		t.Logf("%d cycles failed: %s", failures.Load(), strings.Join(firstErrs, "; "))
	}
	if len(load) == 0 {
		t.Errorf("no load sample was taken in %s (AEROL_SOAK_SAMPLE_SECONDS=%s)", runFor, every)
	}
	if verdict.CountsBack {
		inv.Hold("I6", "%d cycles by %d workers over %s; every count and the placements back at baseline %s after the drain (%d load samples)",
			cycles.Load(), workers, runFor, settleFor.Round(time.Second), len(load))
	} else {
		inv.Violate("I6", "not every count was back at its baseline %s after the drain: %s", settleFor.Round(time.Second), strings.Join(verdict.Problems, "; "))
	}
}

// soakOutPath is AEROL_SOAK_OUT, or <reports>/<scenario>-soak.jsonl next to
// the scenario's other reports.
func soakOutPath() string {
	if p := strings.TrimSpace(os.Getenv("AEROL_SOAK_OUT")); p != "" {
		return p
	}
	dir := os.Getenv("AEROL_REPORTS_DIR")
	if dir == "" {
		dir = filepath.Join("..", "reports")
	}
	return filepath.Join(dir, sc.Name+"-soak.jsonl")
}

// soakCycle is one closed-loop iteration: create, wait for started, run a
// command, delete. A failure is reported through fail and ends the cycle;
// a sandbox it could not delete is left for the drain.
func soakCycle(api *harness.APIClient, req models.CreateSandboxRequest, fail func(string, ...any)) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	r := chaosCreate(ctx, api, req)
	if !r.ok() {
		fail("create %s: %s %v %s", req.Name, r.describe(), r.Err, r.Body)
		time.Sleep(2 * time.Second) // a refused create must not spin
		return
	}
	defer func() {
		for attempt := 0; attempt < 3; attempt++ {
			dctx, dcancel := context.WithTimeout(context.Background(), time.Minute)
			st, err := chaosDelete(dctx, api, r.ID)
			dcancel()
			if err == nil && (st/100 == 2 || st == http.StatusNotFound) {
				return
			}
			if attempt == 2 {
				fail("delete %s: %d %v", r.ID, st, err)
			}
			time.Sleep(2 * time.Second)
		}
	}()
	for started := false; !started; {
		st, sb, err := chaosGetStatus(ctx, api, r.ID)
		switch {
		case err != nil:
			fail("get %s: %v", r.ID, err)
			return
		case st == http.StatusOK && sb.Status == models.SandboxStatusStarted:
			started = true
		case st == http.StatusOK && sb.Status == models.SandboxStatusError:
			fail("sandbox %s entered error: %s", r.ID, sb.LastError)
			return
		default:
			time.Sleep(time.Second)
		}
	}
	want := "soak-" + r.ID
	resp, err := api.Do(ctx, http.MethodPost, execPath(r.ID), models.ExecRequest{Command: "echo " + want})
	var res models.ExecResult
	switch {
	case err != nil:
		fail("exec in %s: %v", r.ID, err)
	case resp.Status != http.StatusOK || resp.JSON(&res) != nil:
		fail("exec in %s: %s", r.ID, resp)
	case res.ExitCode != 0 || strings.TrimSpace(res.Stdout) != want:
		fail("exec in %s: exit %d stdout %q", r.ID, res.ExitCode, res.Stdout)
	}
}

// soakSample reads every node in parallel: the node script over SSH, then
// goroutines and routes from its /v1/metrics. A node whose script failed
// carries the error, never a reading.
func soakSample(t *testing.T, tp chaosTopo, metrics map[string]*harness.APIClient, observer *harness.APIClient, phase string) harness.SoakSample {
	t.Helper()
	s := harness.SoakSample{At: time.Now().UTC(), Phase: phase, Placements: -1, Nodes: map[string]harness.SoakNode{}}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, n := range tp.all() {
		wg.Add(1)
		go func(n harness.IntegrationNode) {
			defer wg.Done()
			node := harness.SoakNode{Role: n.Role}
			target, _ := harness.SSHTarget(n)
			out, err := harness.SSHRun(t, target, harness.SoakNodeScript)
			vals, perr := harness.ParseSoakNode(out)
			switch {
			case err != nil:
				node.Error = fmt.Sprintf("ssh: %v: %s", err, strings.TrimSpace(out))
			case perr != nil:
				node.Error = perr.Error()
			default:
				node.Values = vals
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				resp, merr := metrics[n.Name].Do(ctx, http.MethodGet, "/v1/metrics", nil)
				cancel()
				if merr == nil && resp.Status == http.StatusOK {
					text := string(resp.Body)
					if v, ok := harness.MetricValue(text, "aerolvm_go_goroutines", nil); ok {
						vals["goroutines"] = int64(v)
					}
					if v, ok := harness.MetricValue(text, "aerolvm_ingress_routes_total", nil); ok {
						vals["routes"] = int64(v)
					}
				}
			}
			mu.Lock()
			s.Nodes[n.Name] = node
			mu.Unlock()
		}(n)
	}
	wg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if rows, err := chaosIndex(ctx, observer); err == nil {
		s.Placements = int64(len(rows))
	} else {
		t.Logf("placement count at the %s sample: %v", phase, err)
	}
	return s
}
