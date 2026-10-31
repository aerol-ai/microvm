//go:build integration

package suite

// Scale and stability cases (UC-333..UC-338): concurrent create bursts, API
// and exec throughput, a churn soak that watches the daemon and the node for
// leaks, recovery under load, and density per runtime. Sizes come from the
// environment so the same cases run small on every scenario and large on
// the flagship; each writes its numbers to <reports>/<scenario>-bank.json.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

var bankResultsMu sync.Mutex

// bankRecord merges one case's numbers into the scenario's bank report.
func bankRecord(t *testing.T, key string, v any) {
	t.Helper()
	dir := os.Getenv("AEROL_REPORTS_DIR")
	if dir == "" {
		dir = filepath.Join("..", "reports")
	}
	path := filepath.Join(dir, sc.Name+"-bank.json")
	bankResultsMu.Lock()
	defer bankResultsMu.Unlock()
	all := map[string]any{}
	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, &all)
	}
	all[key] = v
	all["_updated"] = time.Now().UTC().Format(time.RFC3339)
	raw, _ := json.MarshalIndent(all, "", "  ")
	if err := os.MkdirAll(dir, 0o755); err == nil {
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			t.Logf("bank report not written: %v", err)
		}
	}
}

type bankLatency struct {
	N      int     `json:"n"`
	P50MS  float64 `json:"p50_ms"`
	P90MS  float64 `json:"p90_ms"`
	P99MS  float64 `json:"p99_ms"`
	MaxMS  float64 `json:"max_ms"`
	MeanMS float64 `json:"mean_ms"`
}

func bankSummarize(ds []time.Duration) bankLatency {
	if len(ds) == 0 {
		return bankLatency{}
	}
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	q := func(p float64) float64 {
		i := int(math.Ceil(p*float64(len(s)))) - 1
		if i < 0 {
			i = 0
		}
		return float64(s[i].Microseconds()) / 1000
	}
	var sum time.Duration
	for _, d := range s {
		sum += d
	}
	return bankLatency{N: len(s), P50MS: q(0.50), P90MS: q(0.90), P99MS: q(0.99), MaxMS: q(1), MeanMS: float64(sum.Microseconds()) / float64(len(s)) / 1000}
}

// isCapacity reports a clean capacity refusal (503 / no capacity), which a
// burst or density case counts separately from failures.
func bankIsCapacity(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "503") || strings.Contains(s, "capacity") || strings.Contains(s, "insufficient")
}

func bankRuntimes(t *testing.T) []bankRuntime {
	t.Helper()
	return bankShellRuntimes(t)
}

// UC-333 — a burst of concurrent creates: every create either starts a
// sandbox or is refused cleanly for capacity, none fails otherwise, and all
// of them are gone after the burst is destroyed.
func TestBankConcurrentCreateBurst(t *testing.T) {
	harness.Require(t, sc, "UC-333")
	n := benchEnvInt("AEROL_BANK_BURST", 8)
	c := client(t)
	for _, rt := range bankRuntimes(t) {
		t.Run(rt.name, func(t *testing.T) {
			var mu sync.Mutex
			var created []string
			var lat []time.Duration
			var failures []string
			capacity := 0
			var wg sync.WaitGroup
			start := time.Now()
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
					defer cancel()
					t0 := time.Now()
					sb, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
						Image: bankImage(rt), Name: fmt.Sprintf("%s-%d", harness.UniqueName(sc, t), i), Runtime: rt.runtime,
						CPU: 0.25, MemoryMB: 128,
					})
					d := time.Since(t0)
					mu.Lock()
					defer mu.Unlock()
					switch {
					case err == nil:
						created = append(created, sb.ID)
						lat = append(lat, d)
					case bankIsCapacity(err):
						capacity++
					default:
						failures = append(failures, err.Error())
					}
				}(i)
			}
			wg.Wait()
			wall := time.Since(start)
			t.Cleanup(func() {
				for _, id := range created {
					destroyBest(c, id)
				}
			})
			started := 0
			for _, id := range created {
				if bankWaitStarted(c, id, 3*time.Minute) {
					started++
				}
			}
			sum := bankSummarize(lat)
			bankRecord(t, "burst/"+rt.name, map[string]any{"requested": n, "created": len(created), "started": started, "capacity_refused": capacity, "failed": len(failures), "wall_ms": wall.Milliseconds(), "create_latency": sum})
			t.Logf("%s burst of %d: created %d, started %d, capacity-refused %d, failed %d in %v; create %+v", rt.name, n, len(created), started, capacity, len(failures), wall, sum)
			if len(failures) > 0 {
				t.Errorf("%d creates failed for a reason other than capacity: %v", len(failures), bankFirstN(failures, 3))
			}
			if started != len(created) {
				t.Errorf("%d of %d created sandboxes never started", len(created)-started, len(created))
			}
			for _, id := range created {
				destroyBest(c, id)
			}
			created = nil
		})
	}
}

func bankFirstN(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// waitStarted polls a sandbox until it reports started.
func bankWaitStarted(c *harness.Client, id string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		got, err := c.SDK().Get(ctx, id)
		cancel()
		if err == nil && string(got.Status) == "started" {
			return true
		}
		if err == nil && string(got.Status) == "error" {
			return false
		}
		time.Sleep(2 * time.Second)
	}
	return false
}

// UC-334 — API read throughput: concurrent clients list sandboxes and read
// health for a fixed time; no server error, no transport error.
func TestBankAPIThroughput(t *testing.T) {
	harness.Require(t, sc, "UC-334")
	workers := benchEnvInt("AEROL_BANK_API_CONCURRENCY", 16)
	dur := time.Duration(benchEnvInt("AEROL_BANK_API_SECONDS", 20)) * time.Second
	api := harness.NewAPIClient(strings.TrimRight(sc.BaseURL, "/"), sc.PAT)
	for _, path := range []string{"/v1/sandboxes", "/health"} {
		var ok, limited, srvErr, netErr atomic.Int64
		var mu sync.Mutex
		var lat []time.Duration
		ctx, cancel := context.WithTimeout(context.Background(), dur+time.Minute)
		end := time.Now().Add(dur)
		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for time.Now().Before(end) {
					t0 := time.Now()
					resp, err := api.Do(ctx, http.MethodGet, path, nil)
					d := time.Since(t0)
					switch {
					case err != nil:
						netErr.Add(1)
					case resp.Status == http.StatusTooManyRequests:
						limited.Add(1)
					case resp.Status >= 500:
						srvErr.Add(1)
					default:
						ok.Add(1)
						mu.Lock()
						lat = append(lat, d)
						mu.Unlock()
					}
				}
			}()
		}
		wg.Wait()
		cancel()
		sum := bankSummarize(lat)
		rps := float64(ok.Load()) / dur.Seconds()
		bankRecord(t, "api_throughput"+strings.ReplaceAll(path, "/", "_"), map[string]any{"concurrency": workers, "seconds": dur.Seconds(), "ok": ok.Load(), "rate_limited": limited.Load(), "server_errors": srvErr.Load(), "transport_errors": netErr.Load(), "rps": rps, "latency": sum})
		t.Logf("GET %s x%d for %v: %.0f req/s ok, %d rate-limited, %d 5xx, %d transport errors; %+v", path, workers, dur, rps, limited.Load(), srvErr.Load(), netErr.Load(), sum)
		if srvErr.Load() > 0 || netErr.Load() > 0 {
			t.Errorf("GET %s under load: %d server errors, %d transport errors", path, srvErr.Load(), netErr.Load())
		}
	}
}

// UC-335 — exec latency and concurrency per runtime: sequential execs give
// the latency a caller sees; concurrent execs into one sandbox must all
// succeed.
func TestBankExecThroughput(t *testing.T) {
	harness.Require(t, sc, "UC-335")
	seq := benchEnvInt("AEROL_BANK_EXEC_SEQ", 30)
	par := benchEnvInt("AEROL_BANK_EXEC_PAR", 8)
	bankEachRuntime(t, func(t *testing.T, rt bankRuntime) {
		sb := bankSandbox(t, rt, sdktypes.CreateSandboxOptions{})
		var lat []time.Duration
		for i := 0; i < seq; i++ {
			t0 := time.Now()
			if out, rc := bankRun(t, sb, "echo ok", time.Minute); rc != 0 || !strings.Contains(out, "ok") {
				t.Fatalf("exec %d: rc=%d %q", i, rc, out)
			}
			lat = append(lat, time.Since(t0))
		}
		var failed atomic.Int64
		var errMu sync.Mutex
		var errs []string
		var wg sync.WaitGroup
		t0 := time.Now()
		for w := 0; w < par; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < 10; i++ {
					ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
					res, err := sb.ExecCommand(ctx, "echo ok")
					cancel()
					if err != nil || res.ExitCode != 0 {
						failed.Add(1)
						errMu.Lock()
						errs = append(errs, fmt.Sprintf("%v (rc %d)", err, res.ExitCode))
						errMu.Unlock()
					}
				}
			}()
		}
		wg.Wait()
		parWall := time.Since(t0)
		sum := bankSummarize(lat)
		bankRecord(t, "exec/"+rt.name, map[string]any{"sequential": sum, "concurrent_workers": par, "concurrent_execs": par * 10, "concurrent_failed": failed.Load(), "concurrent_wall_ms": parWall.Milliseconds()})
		t.Logf("%s exec: sequential %+v; %d concurrent execs in %v, %d failed", rt.name, sum, par*10, parWall, failed.Load())
		if failed.Load() > 0 {
			t.Errorf("%d of %d concurrent execs failed: %v", failed.Load(), par*10, bankFirstN(errs, 3))
		}
	})
}

// bankNodeVitals is what the churn soak samples on every node.
type bankNodeVitals struct {
	RSSKB    int64 `json:"rss_kb"`
	FDs      int64 `json:"fds"`
	Threads  int64 `json:"threads"`
	Veths    int64 `json:"veths"`
	Taps     int64 `json:"taps"`
	FWRules  int64 `json:"fw_rules"`
	MemAvail int64 `json:"mem_avail_kb"`
}

func bankSampleVitals(t *testing.T, node harness.IntegrationNode) (bankNodeVitals, error) {
	t.Helper()
	target, _ := harness.SSHTarget(node)
	out, err := harness.SSHRun(t, target, `sudo sh -c 'p=$(pidof sandboxd | cut -d" " -f1)
echo rss=$(awk "/VmRSS/ {print \$2}" /proc/$p/status)
echo fds=$(ls /proc/$p/fd | wc -l)
echo threads=$(awk "/Threads/ {print \$2}" /proc/$p/status)
echo veths=$(ip -o link show type veth 2>/dev/null | wc -l)
echo taps=$(ip -o link show type tun 2>/dev/null | wc -l)
echo fw=$( (iptables-save 2>/dev/null; nft list ruleset 2>/dev/null) | wc -l)
echo avail=$(awk "/MemAvailable/ {print \$2}" /proc/meminfo)'`)
	if err != nil {
		return bankNodeVitals{}, fmt.Errorf("%v: %s", err, out)
	}
	var v bankNodeVitals
	for _, l := range strings.Split(out, "\n") {
		k, val, ok := strings.Cut(strings.TrimSpace(l), "=")
		if !ok {
			continue
		}
		n, _ := strconv.ParseInt(strings.TrimSpace(val), 10, 64)
		switch k {
		case "rss":
			v.RSSKB = n
		case "fds":
			v.FDs = n
		case "threads":
			v.Threads = n
		case "veths":
			v.Veths = n
		case "taps":
			v.Taps = n
		case "fw":
			v.FWRules = n
		case "avail":
			v.MemAvail = n
		}
	}
	return v, nil
}

// churn runs workers that each loop create → exec → destroy until stop,
// cycling through rts. It returns per-op latencies and failures.
type bankChurnStats struct {
	mu       sync.Mutex
	cycles   int
	capacity int
	failures []string
	create   []time.Duration
	exec     []time.Duration
	destroy  []time.Duration
}

func bankChurn(t *testing.T, c *harness.Client, rts []bankRuntime, workers int, stop <-chan struct{}, st *bankChurnStats, prefix string) *sync.WaitGroup {
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				rt := rts[(w+i)%len(rts)]
				fail := func(op string, err error) {
					st.mu.Lock()
					defer st.mu.Unlock()
					if bankIsCapacity(err) {
						st.capacity++
						return
					}
					st.failures = append(st.failures, fmt.Sprintf("%s %s: %v", rt.name, op, err))
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
				t0 := time.Now()
				sb, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
					Image: bankImage(rt), Name: fmt.Sprintf("%s-w%d-%d", prefix, w, i), Runtime: rt.runtime, CPU: 0.25, MemoryMB: 256,
				})
				dc := time.Since(t0)
				if err != nil {
					cancel()
					fail("create", err)
					time.Sleep(2 * time.Second)
					continue
				}
				if !bankWaitStarted(c, sb.ID, 3*time.Minute) {
					fail("start", errors.New("never started"))
				}
				t1 := time.Now()
				res, err := sb.ExecCommand(ctx, "echo ok")
				de := time.Since(t1)
				if err != nil || res.ExitCode != 0 {
					fail("exec", fmt.Errorf("%v (rc %d)", err, res.ExitCode))
				}
				t2 := time.Now()
				if err := c.SDK().Destroy(ctx, sb.ID); err != nil {
					fail("destroy", err)
				}
				dd := time.Since(t2)
				cancel()
				st.mu.Lock()
				st.cycles++
				st.create = append(st.create, dc)
				st.exec = append(st.exec, de)
				st.destroy = append(st.destroy, dd)
				st.mu.Unlock()
			}
		}(w)
	}
	return &wg
}

// UC-336 — a churn soak: workers create, use and destroy sandboxes on every
// runtime for AEROL_BANK_CHURN_MINUTES. Failures other than capacity stay
// under 0.5%; on every node the daemon's memory and descriptors level off,
// and veths, TAPs and firewall rules return to where they started; no
// sandbox the soak made is left behind.
func TestBankChurnSoak(t *testing.T) {
	harness.Require(t, sc, "UC-336")
	targets := bankTargets(t)
	minutes := benchEnvInt("AEROL_BANK_CHURN_MINUTES", 3)
	workers := benchEnvInt("AEROL_BANK_CHURN_WORKERS", 4)
	rts := bankRuntimes(t)
	c := client(t)
	prefix := "churn-" + strconv.FormatInt(time.Now().Unix(), 36)
	baseline := map[string]bankNodeVitals{}
	for _, n := range targets.Nodes {
		v, err := bankSampleVitals(t, n)
		if err != nil {
			t.Fatalf("baseline vitals of %s: %v", n.Name, err)
		}
		baseline[n.Name] = v
	}
	samples := map[string][]bankNodeVitals{}
	stop := make(chan struct{})
	st := &bankChurnStats{}
	wg := bankChurn(t, c, rts, workers, stop, st, prefix)
	end := time.Now().Add(time.Duration(minutes) * time.Minute)
	interval := time.Duration(benchEnvInt("AEROL_BANK_CHURN_SAMPLE_SECONDS", 30)) * time.Second
	for time.Now().Before(end) {
		time.Sleep(interval)
		for _, n := range targets.Nodes {
			if v, err := bankSampleVitals(t, n); err == nil {
				samples[n.Name] = append(samples[n.Name], v)
			}
		}
	}
	close(stop)
	wg.Wait()
	// Let async teardown finish before the leak check.
	time.Sleep(time.Duration(benchEnvInt("AEROL_BANK_CHURN_SETTLE_SECONDS", 60)) * time.Second)
	final := map[string]bankNodeVitals{}
	for _, n := range targets.Nodes {
		v, err := bankSampleVitals(t, n)
		if err != nil {
			t.Fatalf("final vitals of %s: %v", n.Name, err)
		}
		final[n.Name] = v
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	list, err := c.SDK().List(ctx)
	if err != nil {
		t.Fatalf("list after the soak: %v", err)
	}
	var leaked []string
	for _, s := range list {
		if strings.HasPrefix(s.Name, prefix) {
			leaked = append(leaked, s.ID)
			destroyBest(c, s.ID)
		}
	}
	st.mu.Lock()
	cycles, capacity, failures := st.cycles, st.capacity, append([]string(nil), st.failures...)
	cs, es, ds := bankSummarize(st.create), bankSummarize(st.exec), bankSummarize(st.destroy)
	st.mu.Unlock()
	rate := 0.0
	if total := cycles + len(failures); total > 0 {
		rate = float64(len(failures)) / float64(total)
	}
	report := map[string]any{"minutes": minutes, "workers": workers, "runtimes": len(rts), "cycles": cycles, "capacity_refused": capacity, "failures": len(failures), "failure_rate": rate,
		"create": cs, "exec": es, "destroy": ds, "leaked_sandboxes": len(leaked), "baseline": baseline, "final": final, "samples": samples}
	bankRecord(t, "churn_soak", report)
	t.Logf("churn soak %dm x%d over %d runtimes: %d cycles, %d capacity refusals, %d failures (%.2f%%); create %+v exec %+v destroy %+v",
		minutes, workers, len(rts), cycles, capacity, len(failures), rate*100, cs, es, ds)
	if rate > 0.005 {
		t.Errorf("failure rate %.2f%% over %d cycles (more than 0.5%%): %v", rate*100, cycles, bankFirstN(failures, 5))
	}
	if len(leaked) > 0 {
		t.Errorf("%d sandboxes the soak made are still listed: %v", len(leaked), bankFirstN(leaked, 5))
	}
	for _, n := range targets.Nodes {
		b, f, s := baseline[n.Name], final[n.Name], samples[n.Name]
		if f.Veths > b.Veths+2 || f.Taps > b.Taps+2 {
			t.Errorf("%s leaks network devices: veths %d -> %d, taps %d -> %d", n.Name, b.Veths, f.Veths, b.Taps, f.Taps)
		}
		if f.FWRules > b.FWRules+40 {
			t.Errorf("%s leaks firewall rules: %d -> %d lines", n.Name, b.FWRules, f.FWRules)
		}
		if f.FDs > b.FDs*3/2+200 {
			t.Errorf("%s: sandboxd holds %d descriptors after the soak (%d before)", n.Name, f.FDs, b.FDs)
		}
		if len(s) >= 6 {
			// Memory must level off: the last third no higher than the
			// middle third by more than 30% (+64 MiB slack for GC timing).
			third := len(s) / 3
			mid, last := bankMeanRSS(s[third:2*third]), bankMeanRSS(s[2*third:])
			if last > mid*13/10+64*1024 {
				t.Errorf("%s: sandboxd memory still climbing at the end of the soak: %d KiB -> %d KiB", n.Name, mid, last)
			}
		}
	}
}

func bankMeanRSS(vs []bankNodeVitals) int64 {
	if len(vs) == 0 {
		return 0
	}
	var sum int64
	for _, v := range vs {
		sum += v.RSSKB
	}
	return sum / int64(len(vs))
}

// UC-337 — recovery under load: while sandboxes churn, the daemon on one
// worker is restarted. Errors are confined to the restart window, the node
// serves again within two minutes, and nothing is leaked.
func TestBankRecoveryUnderLoad(t *testing.T) {
	harness.Require(t, sc, "UC-337")
	targets := bankTargets(t)
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled (set disruptive: true in the scenario caps)")
	}
	var victim harness.IntegrationNode
	for _, n := range targets.Nodes {
		if !n.Seed {
			victim = n
		}
	}
	if victim.Name == "" {
		victim = targets.Nodes[0]
	}
	c := client(t)
	prefix := "recover-" + strconv.FormatInt(time.Now().Unix(), 36)
	stop := make(chan struct{})
	st := &bankChurnStats{}
	wg := bankChurn(t, c, bankRuntimes(t), 2, stop, st, prefix)
	time.Sleep(45 * time.Second)
	restartAt := time.Now()
	nodeSSH(t, victim, "sudo systemctl restart sandboxd")
	t.Cleanup(func() {
		target, _ := harness.SSHTarget(victim)
		restoreNodeDaemon(t, victim, target)
	})
	var back time.Duration
	for deadline := time.Now().Add(3 * time.Minute); ; time.Sleep(3 * time.Second) {
		if strings.Contains(nodeSSH(t, victim, "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:21212/health || true"), "200") {
			back = time.Since(restartAt)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("sandboxd on %s did not come back within 3 minutes", victim.Name)
		}
	}
	if err := waitNodeRejoined(t, victim); err != nil {
		t.Errorf("%s did not rejoin after the restart: %v", victim.Name, err)
	}
	time.Sleep(60 * time.Second)
	close(stop)
	wg.Wait()
	time.Sleep(30 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	list, _ := c.SDK().List(ctx)
	var leaked []string
	for _, s := range list {
		if strings.HasPrefix(s.Name, prefix) {
			leaked = append(leaked, s.ID)
			destroyBest(c, s.ID)
		}
	}
	st.mu.Lock()
	cycles, failures := st.cycles, append([]string(nil), st.failures...)
	st.mu.Unlock()
	bankRecord(t, "recovery_under_load", map[string]any{"victim": victim.Name, "back_after_ms": back.Milliseconds(), "cycles": cycles, "failures": len(failures), "leaked": len(leaked), "sample_failures": bankFirstN(failures, 5)})
	t.Logf("sandboxd on %s back after %v; %d cycles, %d failures during the run, %d leaked", victim.Name, back, cycles, len(failures), len(leaked))
	if back > 2*time.Minute {
		t.Errorf("sandboxd took %v to serve again", back)
	}
	if len(leaked) > 0 {
		t.Errorf("%d sandboxes leaked across the restart: %v", len(leaked), bankFirstN(leaked, 5))
	}
	if cycles > 0 && len(failures) > cycles/2+5 {
		t.Errorf("the restart cost %d failures over %d cycles: %v", len(failures), cycles, bankFirstN(failures, 5))
	}
}

// UC-338 — density per runtime: small sandboxes are created, 8 at a time,
// until the cluster refuses for capacity or AEROL_BANK_DENSITY_MAX is
// reached. The refusal is a clean capacity error, every created sandbox
// runs, and the nodes stay healthy.
func TestBankDensity(t *testing.T) {
	harness.Require(t, sc, "UC-338")
	max := benchEnvInt("AEROL_BANK_DENSITY_MAX", 40)
	c := client(t)
	for _, rt := range bankRuntimes(t) {
		t.Run(rt.name, func(t *testing.T) {
			var mu sync.Mutex
			var created []string
			var failures []string
			capacityHit := false
			var lat []time.Duration
			t.Cleanup(func() {
				var wg sync.WaitGroup
				sem := make(chan struct{}, 8)
				for _, id := range created {
					wg.Add(1)
					sem <- struct{}{}
					go func(id string) { defer wg.Done(); destroyBest(c, id); <-sem }(id)
				}
				wg.Wait()
			})
			for len(created) < max && !capacityHit && len(failures) < 5 {
				var wg sync.WaitGroup
				for i := 0; i < 8 && len(created)+i < max; i++ {
					wg.Add(1)
					go func(i int) {
						defer wg.Done()
						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
						defer cancel()
						t0 := time.Now()
						sb, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
							Image: bankImage(rt), Name: fmt.Sprintf("%s-%d-%d", harness.UniqueName(sc, t), len(created), i), Runtime: rt.runtime, CPU: 0.25, MemoryMB: 128,
						})
						mu.Lock()
						defer mu.Unlock()
						switch {
						case err == nil:
							created = append(created, sb.ID)
							lat = append(lat, time.Since(t0))
						case bankIsCapacity(err):
							capacityHit = true
						default:
							failures = append(failures, err.Error())
						}
					}(i)
				}
				wg.Wait()
			}
			running := 0
			for _, id := range created {
				if bankWaitStarted(c, id, 3*time.Minute) {
					running++
				}
			}
			sum := bankSummarize(lat)
			bankRecord(t, "density/"+rt.name, map[string]any{"max": max, "created": len(created), "running": running, "stopped_on_capacity": capacityHit, "failures": len(failures), "create_latency": sum})
			t.Logf("%s density: %d created (cap %d), %d running, capacity refusal %t, %d failures; create %+v", rt.name, len(created), max, running, capacityHit, len(failures), sum)
			if len(failures) > 0 {
				t.Errorf("%d creates failed for a reason other than capacity: %v", len(failures), bankFirstN(failures, 3))
			}
			if running < len(created) {
				t.Errorf("%d of %d created sandboxes are not running", len(created)-running, len(created))
			}
			// The nodes still serve after being filled.
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if _, err := c.SDK().List(ctx); err != nil {
				t.Errorf("the API stopped answering at density: %v", err)
			}
		})
	}
}
