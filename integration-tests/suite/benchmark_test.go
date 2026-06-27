//go:build integration

package suite

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// benchmark_test.go holds the opt-in create benchmarks (UC-94/UC-95). They run
// only where the scenario advertises CapBenchmark — currently cluster-hetero,
// the one cluster carrying every runtime — because they are slow and provision
// many sandboxes. They reuse the same SDK client + cleanup contract as every
// other use case; the only difference is they record timings instead of
// asserting a single create.
//
// Results are emitted two ways: as t.Logf lines (captured by `go test -json`,
// so they survive into the run log) and, when AEROL_BENCH_OUT is set, as a JSON
// artifact at that path. report/gen.go still classifies UC-94/UC-95 pass/skip
// from the ucid markers like any other UC; the numbers live alongside.

// benchRuntimes is the set of runtimes the latency benchmark sweeps. Each is
// gated on the matching scenario capability, so a scenario missing (say) the
// firecracker worker simply doesn't time that runtime rather than failing.
var benchRuntimes = []struct {
	runtime string
	cap     harness.Capability
}{
	{"docker", harness.CapDocker},
	{"firecracker", harness.CapFirecracker},
	{"gvisor", harness.CapGvisor},
	{"wasm", harness.CapWasm},
}

type benchRuntimeSpec struct {
	runtime string
	wasmRef string
}

// requireBenchEnabled is a second gate on top of the CapBenchmark capability.
// The capability keeps UC-94/UC-95 in the coverage matrix on cluster-hetero,
// but the benchmark is slow and the density probe provisions sandboxes until
// the fleet rejects — far too costly to run on every hetero pass. So it stays
// dormant unless the operator sets AEROL_BENCH=1, in which case it runs as part
// of the normal orchestrated suite (run.sh passes the parent env through). When
// disabled it t.Skips with that reason, which the report shows as a (n/a) skip.
func requireBenchEnabled(t *testing.T) {
	t.Helper()
	if os.Getenv("AEROL_BENCH") != "1" {
		t.Skip("benchmark disabled: set AEROL_BENCH=1 to run UC-94/UC-95 (slow; provisions many sandboxes)")
	}
}

// benchRuntimeAllowed reports whether rt should be swept. AEROL_BENCH_RUNTIMES
// (comma-separated, e.g. "docker,wasm") narrows the sweep — to isolate one
// runtime or skip firecracker's slow cold-boots so a run actually finishes.
// Empty = every runtime the scenario advertises.
func benchRuntimeAllowed(rt string) bool {
	filter := strings.TrimSpace(os.Getenv("AEROL_BENCH_RUNTIMES"))
	if filter == "" {
		return true
	}
	for _, want := range strings.Split(filter, ",") {
		if strings.EqualFold(strings.TrimSpace(want), rt) {
			return true
		}
	}
	return false
}

// benchEnvInt reads a positive integer tunable from env, falling back to def.
func benchEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func selectedBenchRuntimes(t *testing.T) []benchRuntimeSpec {
	t.Helper()
	var selected []benchRuntimeSpec
	for _, br := range benchRuntimes {
		if !sc.Has(br.cap) || !benchRuntimeAllowed(br.runtime) {
			continue
		}
		spec := benchRuntimeSpec{runtime: br.runtime}
		if br.runtime == "wasm" {
			spec.wasmRef = stagedWasmModuleRef(t)
			if spec.wasmRef == "" {
				t.Logf("bench: skipping wasm latency (AEROL_WASM_MODULE_REF unset)")
				continue
			}
		}
		selected = append(selected, spec)
	}
	return selected
}

func benchCreateOptions(t *testing.T, spec benchRuntimeSpec) sdktypes.CreateSandboxOptions {
	t.Helper()
	opts := sdktypes.CreateSandboxOptions{
		Name:    harness.UniqueName(sc, t),
		Runtime: spec.runtime,
	}
	if spec.runtime == "wasm" {
		opts.Image = spec.wasmRef
		opts.ModuleRef = spec.wasmRef
	} else {
		opts.Image = harness.DefaultImage
	}
	return opts
}

func waitBenchmarkReady(t *testing.T, c *harness.Client, runtimes []benchRuntimeSpec) {
	t.Helper()
	if !sc.Has(harness.CapCluster) {
		return
	}
	want, exact := expectedMembers()
	timeout := time.Duration(benchEnvInt("AEROL_BENCH_READY_SECONDS", 300)) * time.Second
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		leader, leaderErr := benchClusterLeader(c)
		members, err := benchClusterMembers(c)
		if err != nil {
			last = err.Error()
			time.Sleep(5 * time.Second)
			continue
		}
		if leaderErr != nil {
			last = "leader: " + leaderErr.Error()
			time.Sleep(5 * time.Second)
			continue
		}
		if leader == "" {
			last = "leader not elected"
			time.Sleep(5 * time.Second)
			continue
		}
		if exact && len(members.Members) != want {
			last = fmt.Sprintf("members=%d want=%d", len(members.Members), want)
			time.Sleep(5 * time.Second)
			continue
		}
		if !exact && len(members.Members) < want {
			last = fmt.Sprintf("members=%d want>=%d", len(members.Members), want)
			time.Sleep(5 * time.Second)
			continue
		}
		if missing := missingBenchRuntimeTargets(members, runtimes); len(missing) > 0 {
			last = "runtime targets not ready: " + strings.Join(missing, ",")
			time.Sleep(5 * time.Second)
			continue
		}
		return
	}
	t.Fatalf("benchmark prerequisites not ready within %s: %s", timeout, last)
}

func benchClusterLeader(c *harness.Client) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var resp struct {
		Leader string `json:"leader"`
	}
	if err := c.GetJSON(ctx, "/v1/cluster/leader", &resp); err != nil {
		return "", err
	}
	return strings.TrimSpace(resp.Leader), nil
}

func benchClusterMembers(c *harness.Client) (capacityView, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var members capacityView
	if err := c.GetJSON(ctx, "/v1/cluster/members", &members); err != nil {
		return capacityView{}, err
	}
	return members, nil
}

func missingBenchRuntimeTargets(members capacityView, runtimes []benchRuntimeSpec) []string {
	var missing []string
	for _, spec := range runtimes {
		if !benchHasRuntimeTarget(members, spec.runtime) {
			missing = append(missing, spec.runtime)
		}
	}
	return missing
}

func benchHasRuntimeTarget(members capacityView, runtime string) bool {
	for _, m := range members.Members {
		if !m.Alive || m.Drained || m.CapacityStale || !benchCanOwnSandbox(m.Role) || !m.Capacity.CanAdmit {
			continue
		}
		for _, rt := range m.Capacity.SupportedRuntimes {
			if rt == runtime {
				return true
			}
		}
	}
	return false
}

func benchCanOwnSandbox(role string) bool {
	role = strings.TrimSpace(role)
	if role == "" {
		return true
	}
	for _, part := range strings.Split(role, ",") {
		switch strings.ToLower(strings.TrimSpace(part)) {
		case "worker", "mixed":
			return true
		}
	}
	return false
}

func warmBenchmarkRuntimes(t *testing.T, c *harness.Client, runtimes []benchRuntimeSpec) {
	t.Helper()
	for _, spec := range runtimes {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		sb, err := c.SDK().Create(ctx, benchCreateOptions(t, spec))
		cancel()
		if err != nil {
			t.Fatalf("bench[%s] warmup create failed after readiness: %v", spec.runtime, err)
		}
		destroy := true
		id := sb.ID
		defer func() {
			if destroy {
				destroyBest(c, id)
			}
		}()
		if !waitRunningTimed(t, sb) {
			t.Fatalf("bench[%s] warmup sandbox %s did not reach started", spec.runtime, id)
		}
		destroyBest(c, id)
		destroy = false
		_, _ = c.LastServerCreateMS()
	}
}

// percentile returns the p-th percentile (0..100) of durs using nearest-rank.
// durs must be non-empty; callers guarantee a sample exists before reporting.
func percentile(durs []time.Duration, p float64) time.Duration {
	sorted := append([]time.Duration(nil), durs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	rank := int(p/100*float64(len(sorted)-1) + 0.5)
	if rank < 0 {
		rank = 0
	}
	if rank >= len(sorted) {
		rank = len(sorted) - 1
	}
	return sorted[rank]
}

// latencyStats is the per-runtime summary written to the JSON artifact.
type latencyStats struct {
	Runtime   string `json:"runtime"`
	Samples   int    `json:"samples"`
	Failures  int    `json:"failures"`
	APIMeanMS int64  `json:"api_mean_ms"` // Create() round-trip
	APIp50MS  int64  `json:"api_p50_ms"`
	APIp90MS  int64  `json:"api_p90_ms"`
	APIp99MS  int64  `json:"api_p99_ms"`
	RunMeanMS int64  `json:"run_mean_ms"` // create-call .. status=started
	Runp50MS  int64  `json:"run_p50_ms"`
	Runp90MS  int64  `json:"run_p90_ms"`
	Runp99MS  int64  `json:"run_p99_ms"`
	// Server-side create time from the API's Server-Timing header — the create
	// cost with the client<->cluster network round-trip excluded. The gap
	// (api - server) is that network overhead. Zero when the server sends no
	// header (older build); ServerSamples counts the creates that carried one.
	ServerSamples int   `json:"server_samples"`
	ServerMeanMS  int64 `json:"server_mean_ms"`
	Serverp50MS   int64 `json:"server_p50_ms"`
	Serverp90MS   int64 `json:"server_p90_ms"`
	Serverp99MS   int64 `json:"server_p99_ms"`
}

// benchReport is the full JSON artifact (UC-94 + UC-95 combined).
type benchReport struct {
	Scenario  string         `json:"scenario"`
	Timestamp string         `json:"timestamp"`
	Machine   *machineConfig `json:"machine,omitempty"`
	Latency   []latencyStats `json:"latency,omitempty"`
	Density   *densityStats  `json:"density,omitempty"`
}

// machineConfig is the hardware the numbers were measured on, copied from the
// scenario's tfvars so a result is self-describing — a create latency is
// meaningless without knowing whether the worker is a t3.medium or a c5.metal.
// It records the intended (terraform-declared) topology, not live-probed specs;
// that's the deliberate trade in keeping the bench tfvars-sourced and offline.
type machineConfig struct {
	Source          string     `json:"source"`           // tfvars path it was read from
	DefaultInstance string     `json:"default_instance"` // default_instance_type
	Nodes           []nodeSpec `json:"nodes"`            // one row per declared node
}

// nodeSpec is one node's declared shape from the tfvars nodes map.
type nodeSpec struct {
	Name         string `json:"name"`
	Role         string `json:"role"`
	InstanceType string `json:"instance_type"` // empty => inherits DefaultInstance
	Extras       string `json:"extras,omitempty"`
}

// tfvarsNodeLine matches a single `name = { ... }` entry in the nodes map.
var tfvarsNodeLine = regexp.MustCompile(`^\s*([A-Za-z0-9_-]+)\s*=\s*\{(.*)\}\s*$`)

// tfvarsAttr pulls a quoted `key = "value"` attribute out of a node body.
func tfvarsAttr(body, key string) string {
	re := regexp.MustCompile(key + `\s*=\s*"([^"]*)"`)
	if m := re.FindStringSubmatch(body); m != nil {
		return m[1]
	}
	return ""
}

// loadMachineConfig parses the scenario's tfvars into a machineConfig. It is
// best-effort: a missing/unreadable file yields nil (logged), never a failure —
// the timings are still useful without the hardware stamp. AEROL_BENCH_TFVARS
// overrides the path; otherwise it defaults to ../scenarios/<scenario>.tfvars
// relative to the suite working directory.
func loadMachineConfig(t *testing.T) *machineConfig {
	t.Helper()
	path := os.Getenv("AEROL_BENCH_TFVARS")
	if path == "" {
		path = filepath.Join("..", "scenarios", sc.Name+".tfvars")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Logf("bench: machine config unavailable (%s): %v", path, err)
		return nil
	}
	mc := &machineConfig{Source: path}
	inNodes := false
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if v := tfvarsAttr(trimmed, "default_instance_type"); v != "" {
			mc.DefaultInstance = v
		}
		switch {
		case strings.HasPrefix(trimmed, "nodes") && strings.Contains(trimmed, "{"):
			inNodes = true
			continue
		case inNodes && trimmed == "}":
			inNodes = false
			continue
		}
		if !inNodes {
			continue
		}
		m := tfvarsNodeLine.FindStringSubmatch(trimmed)
		if m == nil {
			continue
		}
		body := m[2]
		ns := nodeSpec{Name: m[1], Role: tfvarsAttr(body, "role"), InstanceType: tfvarsAttr(body, "instance_type")}
		// Capture the with_* feature flags (with_firecracker/with_gvisor) so the
		// reader knows which runtime a worker was provisioned for.
		var extras []string
		for _, flag := range []string{"with_firecracker", "with_gvisor"} {
			if regexp.MustCompile(flag + `\s*=\s*true`).MatchString(body) {
				extras = append(extras, flag)
			}
		}
		ns.Extras = strings.Join(extras, ",")
		mc.Nodes = append(mc.Nodes, ns)
	}
	return mc
}

// densityStats is the UC-95 summary: how many sandboxes landed before the fleet
// rejected on capacity.
type densityStats struct {
	Runtime       string `json:"runtime"`
	Created       int    `json:"created"`        // reached created (API accepted)
	Running       int    `json:"running"`        // reached status=started
	StoppedOnCap  bool   `json:"stopped_on_cap"` // hit a capacity rejection
	StoppedReason string `json:"stopped_reason"` // error that ended the probe
	SafetyCapHit  bool   `json:"safety_cap_hit"` // hit AEROL_BENCH_MAX before any rejection
}

// writeBenchArtifact persists the report when AEROL_BENCH_OUT is set. Failure to
// write is logged, never fatal: the t.Logf numbers are the source of record.
func writeBenchArtifact(t *testing.T, rep benchReport) {
	t.Helper()
	out := os.Getenv("AEROL_BENCH_OUT")
	if out == "" {
		return
	}
	rep.Scenario = sc.Name
	rep.Timestamp = time.Now().UTC().Format(time.RFC3339)
	rep.Machine = loadMachineConfig(t)
	blob, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		t.Logf("bench: marshal artifact: %v", err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		t.Logf("bench: mkdir %s: %v", filepath.Dir(out), err)
		return
	}
	if err := os.WriteFile(out, blob, 0o644); err != nil {
		t.Logf("bench: write artifact %s: %v", out, err)
	}
}

// UC-94 — measure per-runtime create latency. For each runtime the scenario
// supports, create AEROL_BENCH_SAMPLES sandboxes serially, recording the
// Create() round-trip and the full create→running time, then report p50/p90/p99.
func TestBenchCreateLatency(t *testing.T) {
	harness.Require(t, sc, "UC-94")
	requireBenchEnabled(t)
	c := client(t)
	samples := benchEnvInt("AEROL_BENCH_SAMPLES", 10)
	runtimes := selectedBenchRuntimes(t)
	if len(runtimes) == 0 {
		t.Skip("no benchmark runtimes selected")
	}
	waitBenchmarkReady(t, c, runtimes)
	warmBenchmarkRuntimes(t, c, runtimes)

	var report benchReport
	for _, br := range runtimes {
		var apiD, runD, serverD []time.Duration
		failures := 0
		for i := 0; i < samples; i++ {
			opts := benchCreateOptions(t, br)

			start := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			sb, err := c.SDK().Create(ctx, opts)
			apiElapsed := time.Since(start)
			cancel()
			if err != nil {
				failures++
				t.Logf("bench[%s] sample %d create failed: %v", br.runtime, i, err)
				continue
			}
			// Guaranteed teardown even on a panic/fatal in the loop.
			id := sb.ID
			t.Cleanup(func() { destroyBest(c, id) })

			if waitRunningTimed(t, sb) {
				runD = append(runD, time.Since(start))
			} else {
				failures++
			}
			apiD = append(apiD, apiElapsed)
			// Server-reported create time (Server-Timing header) — same create,
			// minus the client<->cluster network. Absent on an older server.
			if ms, ok := c.LastServerCreateMS(); ok {
				serverD = append(serverD, time.Duration(ms*float64(time.Millisecond)))
			}
		}

		if len(apiD) == 0 {
			t.Errorf("bench[%s]: every create sample failed", br.runtime)
			continue
		}
		ls := summarize(br.runtime, samples, failures, apiD, runD, serverD)
		report.Latency = append(report.Latency, ls)
		t.Logf("bench[%s] api p50=%dms p90=%dms p99=%dms | server p50=%dms p90=%dms p99=%dms | running p50=%dms p90=%dms p99=%dms (%d ok, %d fail)",
			br.runtime, ls.APIp50MS, ls.APIp90MS, ls.APIp99MS,
			ls.Serverp50MS, ls.Serverp90MS, ls.Serverp99MS,
			ls.Runp50MS, ls.Runp90MS, ls.Runp99MS, len(apiD), failures)
	}
	writeBenchArtifact(t, report)
}

// summarize folds raw samples into a latencyStats row.
func summarize(rt string, samples, failures int, apiD, runD, serverD []time.Duration) latencyStats {
	ls := latencyStats{Runtime: rt, Samples: samples, Failures: failures}
	if len(apiD) > 0 {
		ls.APIMeanMS = meanMS(apiD)
		ls.APIp50MS = percentile(apiD, 50).Milliseconds()
		ls.APIp90MS = percentile(apiD, 90).Milliseconds()
		ls.APIp99MS = percentile(apiD, 99).Milliseconds()
	}
	if len(runD) > 0 {
		ls.RunMeanMS = meanMS(runD)
		ls.Runp50MS = percentile(runD, 50).Milliseconds()
		ls.Runp90MS = percentile(runD, 90).Milliseconds()
		ls.Runp99MS = percentile(runD, 99).Milliseconds()
	}
	if len(serverD) > 0 {
		ls.ServerSamples = len(serverD)
		ls.ServerMeanMS = meanMS(serverD)
		ls.Serverp50MS = percentile(serverD, 50).Milliseconds()
		ls.Serverp90MS = percentile(serverD, 90).Milliseconds()
		ls.Serverp99MS = percentile(serverD, 99).Milliseconds()
	}
	return ls
}

func meanMS(durs []time.Duration) int64 {
	var sum time.Duration
	for _, d := range durs {
		sum += d
	}
	return (sum / time.Duration(len(durs))).Milliseconds()
}

// UC-95 — density probe: create docker sandboxes until the fleet rejects on
// capacity, then tear them all down. Docker is used because it's the densest
// runtime and present on every cluster scenario, making the ceiling a stable
// signal. A safety cap (AEROL_BENCH_MAX) bounds cost if admission never trips.
func TestBenchDensity(t *testing.T) {
	harness.Require(t, sc, "UC-95")
	requireBenchEnabled(t)
	if !benchRuntimeAllowed("docker") {
		t.Skip("AEROL_BENCH_RUNTIMES excludes docker; density probe is docker-only")
	}
	c := client(t)
	dockerBench := []benchRuntimeSpec{{runtime: "docker"}}
	waitBenchmarkReady(t, c, dockerBench)
	warmBenchmarkRuntimes(t, c, dockerBench)
	maxSandboxes := benchEnvInt("AEROL_BENCH_MAX", 200)

	ds := densityStats{Runtime: "docker"}
	var ids []string
	// Destroy everything we created, even on a fatal. Done in parallel to keep
	// teardown bounded when the count is large.
	t.Cleanup(func() { destroyAll(c, ids) })

	for i := 0; i < maxSandboxes; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		sb, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
			Name:    harness.UniqueName(sc, t),
			Image:   harness.DefaultImage,
			Runtime: "docker",
		})
		cancel()
		if err != nil {
			if isCapacityRejection(err) {
				ds.StoppedOnCap = true
				ds.StoppedReason = err.Error()
				break
			}
			// A non-capacity error is a real failure of the probe, not the
			// ceiling we're measuring.
			t.Fatalf("bench density: create %d failed with non-capacity error: %v", i, err)
		}
		ids = append(ids, sb.ID)
		ds.Created++
		if waitRunningTimed(t, sb) {
			ds.Running++
		}
	}
	if !ds.StoppedOnCap {
		ds.SafetyCapHit = true
		t.Logf("bench density: reached safety cap %d without a capacity rejection; "+
			"the true ceiling is higher — raise AEROL_BENCH_MAX to find it", maxSandboxes)
	}
	t.Logf("bench density: created=%d running=%d stopped_on_cap=%v", ds.Created, ds.Running, ds.StoppedOnCap)
	writeBenchArtifact(t, benchReport{Density: &ds})
}

// isCapacityRejection reports whether err is the fleet refusing on capacity
// (host or cluster admission). Both error strings contain "capacity exceeded";
// the SDK surfaces the body text on a 503, so a substring match is the stable
// seam without importing server packages into the integration client.
func isCapacityRejection(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "capacity exceeded") ||
		strings.Contains(msg, "capacity") && strings.Contains(msg, "exceeded")
}

// waitRunningTimed is waitRunning's non-fatal sibling: it returns false on
// timeout/error instead of failing the test, so a single slow sandbox doesn't
// abort a whole benchmark sweep. It logs the reason for the miss.
func waitRunningTimed(t *testing.T, sb *microvm.Sandbox) bool {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for {
		switch string(sb.Status) {
		case "started":
			return true
		case "error":
			t.Logf("bench: sandbox %s entered error state: %s", sb.ID, sb.LastError)
			return false
		}
		if time.Now().After(deadline) {
			t.Logf("bench: sandbox %s never reached started (last status %q)", sb.ID, sb.Status)
			return false
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := sb.Refresh(ctx)
		cancel()
		if err != nil {
			t.Logf("bench: refresh %s: %v", sb.ID, err)
			return false
		}
		time.Sleep(2 * time.Second)
	}
}

// destroyBest tears down one sandbox, ignoring errors (cleanup is best-effort).
func destroyBest(c *harness.Client, id string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_ = c.SDK().Destroy(ctx, id)
}

// destroyAll tears down many sandboxes concurrently with a small worker bound,
// so density teardown stays quick without hammering the API.
func destroyAll(c *harness.Client, ids []string) {
	const workers = 8
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		sem <- struct{}{}
		go func(id string) {
			defer wg.Done()
			defer func() { <-sem }()
			destroyBest(c, id)
		}(id)
	}
	wg.Wait()
}
