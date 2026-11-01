//go:build integration

package suite

// UC-361: overload is shed, never turned into an outage.
//
// The finding it answers (bank flagship ramp, 2026-11-01, main faedbfc2):
// GET /v1/sandboxes through the domain held 887 req/s at 256 clients, then
// collapsed — 167 req/s with a 5.6 s p99 at 512, and at 1024 a 37 s p99 and
// 5,081 502s. Every list on an ingress made its own control-plane read and,
// when that timed out, asked every worker; the 2-vCPU ingress spent itself
// on mTLS handshakes. Its /health then missed one watchdog probe, the
// watchdog restarted an alive node, the stop ran into SIGKILL, and the next
// probe restarted the new daemon 70 ms into its boot. Caddy answered 502
// and "connection refused" the whole time.
//
// What it asserts, driving AEROL_OVERLOAD_CONCURRENCY clients (default
// 1024, the step that broke) at the public domain for AEROL_OVERLOAD_SECONDS
// (default 60):
//   - every answer is 200 or a refusal that says when to come back (503 or
//     429 with Retry-After); never 502/504, any other 5xx, a connection
//     refused or reset, or a request left hanging past 30 s;
//   - no sandboxd on any node restarted: the unit's InvocationID and
//     NRestarts are unchanged (the watchdog's restarts do not count in
//     NRestarts), and neither the unit's journal nor the watchdog's shows a
//     start or a restart since the load began;
//   - within 60 s of the load stopping, the list is back to its baseline
//     latency.
//
// It reports each node's aerolvm_api_list_shed_total so a run that never
// reached the shedding point says so instead of passing quietly.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
)

// overloadDaemonRun identifies one run of sandboxd on a node.
type overloadDaemonRun struct {
	invocation string
	restarts   string
	mainPID    string
	since      int64 // the node's clock when the run was read
}

func overloadReadDaemonRun(t *testing.T, node harness.IntegrationNode) (overloadDaemonRun, error) {
	t.Helper()
	target, _ := harness.SSHTarget(node)
	out, err := harness.SSHRun(t, target, `date +%s; systemctl show -p InvocationID -p NRestarts -p MainPID sandboxd`)
	if err != nil {
		return overloadDaemonRun{}, fmt.Errorf("%v: %s", err, out)
	}
	var run overloadDaemonRun
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		key, value, ok := strings.Cut(line, "=")
		switch {
		case !ok:
			if n, err := strconv.ParseInt(line, 10, 64); err == nil {
				run.since = n
			}
		case key == "InvocationID":
			run.invocation = value
		case key == "NRestarts":
			run.restarts = value
		case key == "MainPID":
			run.mainPID = value
		}
	}
	if run.invocation == "" || run.since == 0 {
		return run, fmt.Errorf("could not read sandboxd's run: %q", out)
	}
	return run, nil
}

// overloadRestartsSince counts sandboxd starts and watchdog restarts in the
// node's journal since epoch.
func overloadRestartsSince(t *testing.T, node harness.IntegrationNode, epoch int64) (starts, watchdog int, err error) {
	t.Helper()
	target, _ := harness.SSHTarget(node)
	script := fmt.Sprintf(`sudo journalctl -u sandboxd --since @%d --no-pager | grep -c 'Started .*AerolVM daemon' || true
sudo journalctl -t sandboxd-healthcheck --since @%d --no-pager | grep -c 'restarting sandboxd.service' || true`, epoch, epoch)
	out, err := harness.SSHRun(t, target, script)
	if err != nil {
		return 0, 0, fmt.Errorf("%v: %s", err, out)
	}
	var counts []int
	for _, line := range strings.Split(out, "\n") {
		if n, err := strconv.Atoi(strings.TrimSpace(line)); err == nil {
			counts = append(counts, n)
		}
	}
	if len(counts) != 2 {
		return 0, 0, fmt.Errorf("unexpected journal counts %q", out)
	}
	return counts[0], counts[1], nil
}

// overloadShedTotal reads aerolvm_api_list_shed_total on a node (the PAT
// goes over stdin, never onto a command line). Informational only.
func overloadShedTotal(t *testing.T, node harness.IntegrationNode) string {
	t.Helper()
	target, _ := harness.SSHTarget(node)
	out, err := harness.SSHRunStdin(t, target, `read -r pat; curl -s -m 10 -H "Authorization: Bearer $pat" http://127.0.0.1:21212/v1/metrics | grep -E '^aerolvm_api_list_shed_total ' | awk '{print $2}'`, sc.PAT+"\n")
	if err != nil {
		return "?"
	}
	if v := strings.TrimSpace(out); v != "" {
		return v
	}
	return "0"
}

// overloadClip keeps a failure sample short enough to group by.
func overloadClip(s string) string {
	if len(s) > 120 {
		return s[:120]
	}
	return s
}

func overloadP50(ds []time.Duration) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[len(s)/2]
}

// UC-361 — N× list load through the domain is shed (503/429 + Retry-After),
// no sandboxd restarts, and the API is back to baseline within 60 s.
func TestOverloadShedsInsteadOfRestarting(t *testing.T) {
	harness.Require(t, sc, "UC-361")
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled (set disruptive: true in the scenario caps)")
	}
	targets := harness.LoadIntegrationTargets()
	if targets == nil || len(targets.Nodes) == 0 {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	for _, node := range targets.Nodes {
		harness.RequireNodeSSH(t, node)
	}
	workers := benchEnvInt("AEROL_OVERLOAD_CONCURRENCY", 1024)
	dur := time.Duration(benchEnvInt("AEROL_OVERLOAD_SECONDS", 60)) * time.Second
	const (
		requestBudget  = 30 * time.Second // "queued until it took 30 s" is the failure
		recoveryWindow = 60 * time.Second
	)
	api := harness.NewAPIClient(strings.TrimRight(sc.BaseURL, "/"), sc.PAT)

	// 1. Which run of sandboxd each node is on.
	before := map[string]overloadDaemonRun{}
	for _, node := range targets.Nodes {
		run, err := overloadReadDaemonRun(t, node)
		if err != nil {
			t.Fatalf("%s: %v", node.Name, err)
		}
		before[node.Name] = run
	}

	// 2. Baseline: sequential lists on an idle API.
	var baseline []time.Duration
	for i := 0; i < 20; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), requestBudget)
		t0 := time.Now()
		resp, err := api.Do(ctx, http.MethodGet, "/v1/sandboxes", nil)
		cancel()
		if err != nil || resp.Status != http.StatusOK {
			t.Fatalf("baseline list %d: %v %s", i, err, resp.String())
		}
		baseline = append(baseline, time.Since(t0))
	}
	baseP50 := overloadP50(baseline)
	// Back to baseline: the median of 5 lists in a row within this bound.
	recovered := max(2*baseP50, baseP50+250*time.Millisecond)

	// 3. The storm.
	var ok, shed, shedNoRetryAfter, badStatus, transport, hung atomic.Int64
	var mu sync.Mutex
	var okLat, shedLat []time.Duration
	samples := map[string]int{}
	note := func(kind string) {
		mu.Lock()
		samples[kind]++
		mu.Unlock()
	}
	end := time.Now().Add(dur)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(end) {
				ctx, cancel := context.WithTimeout(context.Background(), requestBudget)
				t0 := time.Now()
				resp, err := api.Do(ctx, http.MethodGet, "/v1/sandboxes", nil)
				d := time.Since(t0)
				cancel()
				switch {
				case err != nil && errors.Is(err, context.DeadlineExceeded):
					hung.Add(1)
					note("hung past 30s")
				case err != nil:
					transport.Add(1)
					note("transport: " + overloadClip(err.Error()))
				case resp.Status == http.StatusOK:
					ok.Add(1)
					mu.Lock()
					okLat = append(okLat, d)
					mu.Unlock()
				case resp.Status == http.StatusServiceUnavailable || resp.Status == http.StatusTooManyRequests:
					if resp.Header.Get("Retry-After") == "" {
						shedNoRetryAfter.Add(1)
						note(fmt.Sprintf("%d without Retry-After: %s", resp.Status, resp.String()))
						continue
					}
					shed.Add(1)
					mu.Lock()
					shedLat = append(shedLat, d)
					mu.Unlock()
				default:
					badStatus.Add(1)
					note(fmt.Sprintf("status %d: %s", resp.Status, overloadClip(resp.String())))
				}
			}
		}()
	}
	wg.Wait()
	stormEnd := time.Now()

	// 4. Recovery: back to baseline latency within the window.
	var recent []time.Duration
	recoveredAfter := time.Duration(-1)
	for time.Since(stormEnd) < recoveryWindow {
		ctx, cancel := context.WithTimeout(context.Background(), requestBudget)
		t0 := time.Now()
		resp, err := api.Do(ctx, http.MethodGet, "/v1/sandboxes", nil)
		d := time.Since(t0)
		cancel()
		if err != nil || resp.Status != http.StatusOK {
			recent = recent[:0]
		} else {
			recent = append(recent, d)
			if len(recent) > 5 {
				recent = recent[1:]
			}
			if len(recent) == 5 && overloadP50(recent) <= recovered {
				recoveredAfter = time.Since(stormEnd)
				break
			}
		}
		time.Sleep(time.Second)
	}

	// 5. No sandboxd restarted anywhere.
	sheds := map[string]string{}
	var restarted []string
	for _, node := range targets.Nodes {
		was := before[node.Name]
		now, err := overloadReadDaemonRun(t, node)
		if err != nil {
			t.Errorf("%s: %v", node.Name, err)
			continue
		}
		starts, watchdog, err := overloadRestartsSince(t, node, was.since)
		if err != nil {
			t.Errorf("%s: %v", node.Name, err)
			continue
		}
		if now.invocation != was.invocation || now.restarts != was.restarts || starts > 0 || watchdog > 0 {
			restarted = append(restarted, fmt.Sprintf("%s (InvocationID %s→%s, NRestarts %s→%s, MainPID %s→%s, %d start(s) and %d watchdog restart(s) in the journal)",
				node.Name, was.invocation, now.invocation, was.restarts, now.restarts, was.mainPID, now.mainPID, starts, watchdog))
		}
		sheds[node.Name] = overloadShedTotal(t, node)
	}

	okSum, shedSum := bankSummarize(okLat), bankSummarize(shedLat)
	recoveredMS := int64(-1) // never
	if recoveredAfter >= 0 {
		recoveredMS = recoveredAfter.Milliseconds()
	}
	bankRecord(t, "overload_shed_v1_sandboxes", map[string]any{
		"concurrency": workers, "seconds": dur.Seconds(),
		"ok": ok.Load(), "shed": shed.Load(), "refused_without_retry_after": shedNoRetryAfter.Load(),
		"bad_status": badStatus.Load(), "transport_errors": transport.Load(), "hung": hung.Load(),
		"ok_rps": float64(ok.Load()) / dur.Seconds(), "ok_latency": okSum, "shed_latency": shedSum,
		"baseline_p50_ms": baseP50.Milliseconds(), "recovered_after_ms": recoveredMS,
		"shed_total_by_node": sheds, "restarted": restarted, "failure_samples": samples,
	})
	t.Logf("GET /v1/sandboxes x%d for %v: %d ok (%.0f req/s, %+v), %d shed with Retry-After (%+v); baseline p50 %v, back to baseline %v after the load; shed totals by node %v",
		workers, dur, ok.Load(), float64(ok.Load())/dur.Seconds(), okSum, shed.Load(), shedSum, baseP50, recoveredAfter, sheds)
	if shed.Load() == 0 {
		t.Logf("no request was shed: %d clients did not reach this cluster's shedding point; raise AEROL_OVERLOAD_CONCURRENCY to exercise it", workers)
	}

	if len(restarted) > 0 {
		t.Errorf("sandboxd restarted under load: %s", strings.Join(restarted, "; "))
	}
	if n := badStatus.Load() + shedNoRetryAfter.Load() + transport.Load() + hung.Load(); n > 0 {
		t.Errorf("%d requests failed other than as a refusal with Retry-After (bad status %d, refusal without Retry-After %d, transport %d, hung past %v %d); samples %v",
			n, badStatus.Load(), shedNoRetryAfter.Load(), transport.Load(), requestBudget, hung.Load(), samples)
	}
	if recoveredAfter < 0 {
		t.Errorf("the list was not back to its baseline (median of 5 within %v; baseline p50 %v) within %v of the load stopping; last %v", recovered, baseP50, recoveryWindow, recent)
	}
}
