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
// only where the scenario advertises CapBenchmark — cluster-hetero (every
// runtime), cluster-3-mixed-docker (docker only), cluster-3-mixed-fc (docker +
// firecracker), cluster-3-mixed-gvisor (docker + gvisor), and cluster-3-mixed-wasm
// (docker + wasm) — because they
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
	// docker-cold is the same docker runtime forced past the warm container
	// pool (see benchCreateOptions), so a pool-enabled scenario reports the
	// cold floor next to the warm-hit row instead of losing it. On a
	// pool-less scenario the two rows converge — cheap redundancy.
	{"docker-cold", harness.CapDocker},
	// containerd is a host ENGINE, not a runtime: a containerd node runs the
	// same runc-backed OCI runtime and advertises "docker" in supported_runtimes
	// (benchClusterRuntime maps this row back to "docker"), so the create itself
	// is a plain docker create that the native containerd driver serves. The row
	// exists only so the cluster-3-mixed-containerd artifact labels the engine
	// distinctly from the docker baseline. Gated on CapContainerdEngine so it
	// sweeps ONLY on containerd scenarios — the make target still narrows the
	// sweep to just this row with AEROL_BENCH_RUNTIMES=containerd.
	{"containerd", harness.CapContainerdEngine},
	{"firecracker", harness.CapFirecracker},
	{"gvisor", harness.CapGvisor},
	{"wasm", harness.CapWasm},
}

type benchRuntimeSpec struct {
	runtime    string
	image      string
	wasmRef    string
	templateID string
}

// requireBenchEnabled is a second gate on top of the CapBenchmark capability.
// The capability keeps UC-94/UC-95 in the coverage matrix on benchmark-capable
// scenarios (cluster-hetero, cluster-3-mixed-docker, cluster-3-mixed-fc,
// cluster-3-mixed-gvisor, cluster-3-mixed-wasm), but the benchmark is slow and
// the density probe provisions sandboxes until
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

// verifyNetrulesBackend fails the benchmark when the cluster is not running
// the netrules backend named in AEROL_BENCH_EXPECT_NETRULES (exec|netlink).
// SB_NETRULES_BACKEND is node-side provisioning config the bench cannot set
// from here — without this gate a run intended to measure the netlink backend
// (plans/warm-create-latency-tier1.md Phase 1) silently benches exec and the
// numbers look plausible. Scrapes aerolvm_netrules_backend from /v1/metrics;
// the scrape sees the node that answers it, which stands for the cluster
// because provisioning applies one .env template to every node. Unset env
// means no expectation — the gate is opt-in per run.
func verifyNetrulesBackend(t *testing.T, c *harness.Client) {
	t.Helper()
	want := strings.ToLower(strings.TrimSpace(os.Getenv("AEROL_BENCH_EXPECT_NETRULES")))
	if want == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	body, err := c.GetText(ctx, "/v1/metrics")
	if err != nil {
		t.Fatalf("bench gate: scrape /v1/metrics for netrules backend: %v", err)
	}
	needle := fmt.Sprintf("aerolvm_netrules_backend{key=%q}", want)
	var seen []string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "aerolvm_netrules_backend{") {
			continue
		}
		seen = append(seen, line)
		if strings.HasPrefix(line, needle) && !strings.HasSuffix(line, " 0") {
			t.Logf("bench gate: netrules backend %q confirmed (%s)", want, line)
			return
		}
	}
	report := strings.Join(seen, "; ")
	if report == "" {
		report = "metric absent — server build predates aerolvm_netrules_backend"
	}
	t.Fatalf("bench gate: cluster is not running netrules backend %q — set SB_NETRULES_BACKEND on the nodes and restart sandboxd (server reports: %s)",
		want, report)
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
	switch spec.runtime {
	case "wasm":
		opts.Image = spec.wasmRef
		opts.ModuleRef = spec.wasmRef
	case "firecracker":
		opts.Image = spec.image
		if opts.Image == "" {
			opts.Image = harness.DefaultImage
		}
		if spec.templateID != "" {
			opts.TemplateID = spec.templateID
		}
	case "docker-cold":
		// The row name is docker-cold; the create itself is a plain docker
		// create forced past the warm container pool: any Env entry makes
		// poolEligible reject it, so every sample measures the cold engine
		// path. The pause-netns pool still applies when enabled — it IS the
		// cold path's accelerator, and this row is how its win is measured.
		opts.Runtime = "docker"
		opts.Image = harness.DefaultImage
		opts.Env = map[string]string{"AEROL_BENCH_COLD": "1"}
	case "containerd":
		// containerd is the host engine, reached via the "docker" runtime
		// (the node advertises "docker"). This scenario runs no warm pool
		// (docker-pool/containerd-pool caps absent), so every create already
		// takes the cold engine path — the honest baseline against docker-cold.
		opts.Runtime = "docker"
		opts.Image = harness.DefaultImage
	default:
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

// benchClusterRuntime maps a UC-94 row name to the runtime string cluster
// gossip advertises in supported_runtimes. docker-cold is a pool-ineligible
// docker variant for the bench artifact, not a distinct engine; containerd is
// the host engine backing the same runc-backed "docker" runtime — a containerd
// node advertises "docker" in supported_runtimes, so its readiness target is
// checked under "docker" too.
func benchClusterRuntime(runtime string) string {
	switch runtime {
	case "docker-cold", "containerd":
		return "docker"
	}
	return runtime
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
	clusterRT := benchClusterRuntime(runtime)
	for _, m := range members.Members {
		if !m.Alive || m.Drained || m.CapacityStale || !benchCanOwnSandbox(m.Role) || !m.Capacity.CanAdmit {
			continue
		}
		for _, rt := range m.Capacity.SupportedRuntimes {
			if rt == clusterRT {
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

// waitDockerPoolWarm blocks until a docker create is served from the warm
// container pool (or a timeout passes). Without this gate the bench races the
// pool's own self-warming: the suite runs right after node bootstrap, the
// first creates all record misses (which is what REGISTERS the miss-driven
// refill targets), and every sample measures the cold path — exactly the
// v0.5.29 bench artifact, where docker_pool read 0ms on all ten samples. A
// warm hit is a create whose Server-Timing has a docker_pool stage but no
// docker_create stage (an adopted container never hits /containers/create).
// Timing out is logged, not fatal: the samples still run and the stage
// breakdown in the artifact shows the misses.
func waitDockerPoolWarm(t *testing.T, c *harness.Client, runtimes []benchRuntimeSpec) {
	t.Helper()
	if !sc.Has(harness.CapDockerPool) {
		return
	}
	benchesDocker := false
	for _, spec := range runtimes {
		if spec.runtime == "docker" || spec.runtime == "" {
			benchesDocker = true
		}
	}
	if !benchesDocker {
		return
	}
	deadline := time.Now().Add(time.Duration(benchEnvInt("AEROL_BENCH_POOL_WARM_SECONDS", 120)) * time.Second)
	attempt := 0
	for time.Now().Before(deadline) {
		attempt++
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		sb, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
			Name:  harness.UniqueName(sc, t),
			Image: harness.DefaultImage,
		})
		cancel()
		if err != nil {
			t.Logf("bench[docker] pool-warm probe %d create failed: %v", attempt, err)
			time.Sleep(5 * time.Second)
			continue
		}
		stages, ok := c.LastServerCreateStages()
		destroyBest(c, sb.ID)
		if ok {
			_, pool := stages["docker_pool"]
			_, cold := stages["docker_create"]
			if pool && !cold {
				t.Logf("bench[docker] warm pool serving hits after %d probe(s)", attempt)
				return
			}
		}
		time.Sleep(5 * time.Second)
	}
	t.Logf("bench[docker] warm pool never served a hit within the warm window; samples will include misses")
}

func prepareBenchmarkRuntimes(t *testing.T, c *harness.Client, runtimes []benchRuntimeSpec) []benchRuntimeSpec {
	t.Helper()
	prepared := append([]benchRuntimeSpec(nil), runtimes...)
	for i := range prepared {
		if prepared[i].runtime == "firecracker" {
			templateID, image := createBenchmarkFirecrackerTemplate(t, c)
			prepared[i].templateID = templateID
			prepared[i].image = image
		}
	}
	return prepared
}

func createBenchmarkFirecrackerTemplate(t *testing.T, c *harness.Client) (string, string) {
	t.Helper()
	image := strings.TrimSpace(os.Getenv("AEROL_BENCH_FC_TEMPLATE_IMAGE"))
	if image == "" {
		image = "docker://" + harness.DefaultImage
	}
	createImage := strings.TrimPrefix(image, "docker://")
	if createImage == "" {
		createImage = harness.DefaultImage
	}
	ctx, cancel := context.WithTimeout(context.Background(), 18*time.Minute)
	tmpl, err := c.SDK().CreateTemplate(ctx, sdktypes.CreateTemplateOptions{Image: image})
	cancel()
	if err != nil {
		t.Fatalf("bench[firecracker] create template: %v", err)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), time.Minute)
		defer ccancel()
		_ = c.SDK().DeleteTemplate(cctx, tmpl.ID)
	})
	t.Logf("bench[firecracker] waiting for template %s (%s)", tmpl.ID, image)
	waitTemplateReady(t, c, tmpl.ID)
	t.Logf("bench[firecracker] template %s ready; measuring snapshot clones", tmpl.ID)
	return tmpl.ID, createImage
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
	// Stages is the per-stage Server-Timing breakdown (Phase 0 of
	// plans/firecracker-create-latency.md): one entry per <name>;dur=
	// metric the server reported (fc_verify, fc_spawn, fc_driver, …).
	// Empty for servers that only send create;dur=. Samples counts the
	// creates whose header carried that stage — a stage absent from
	// some samples (e.g. fc_warm on a cold fallback) reports fewer.
	Stages map[string]stageStats `json:"stages,omitempty"`
}

// stageStats folds one named stage's samples across the bench run.
type stageStats struct {
	Samples int   `json:"samples"`
	MeanMS  int64 `json:"mean_ms"`
	P50MS   int64 `json:"p50_ms"`
}

// benchReport is the full JSON artifact (UC-94 + UC-95 combined).
type benchReport struct {
	Scenario  string         `json:"scenario"`
	Timestamp string         `json:"timestamp"`
	Machine   *machineConfig `json:"machine,omitempty"`
	Latency   []latencyStats `json:"latency,omitempty"`
	Density   *densityStats  `json:"density,omitempty"`
}

var benchArtifactMu sync.Mutex

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

func mergeBenchReports(base, update benchReport) benchReport {
	if update.Latency != nil {
		base.Latency = update.Latency
	}
	if update.Density != nil {
		base.Density = update.Density
	}
	return base
}

// writeBenchArtifact persists the report when AEROL_BENCH_OUT is set. Failure to
// write is logged, never fatal: the t.Logf numbers are the source of record.
func writeBenchArtifact(t *testing.T, rep benchReport) {
	t.Helper()
	out := os.Getenv("AEROL_BENCH_OUT")
	if out == "" {
		return
	}
	benchArtifactMu.Lock()
	defer benchArtifactMu.Unlock()
	if raw, err := os.ReadFile(out); err == nil && strings.TrimSpace(string(raw)) != "" {
		var existing benchReport
		if err := json.Unmarshal(raw, &existing); err != nil {
			t.Logf("bench: read existing artifact %s: %v", out, err)
		} else {
			rep = mergeBenchReports(existing, rep)
		}
	} else if err != nil && !os.IsNotExist(err) {
		t.Logf("bench: read existing artifact %s: %v", out, err)
	}

	rep.Scenario = sc.Name
	rep.Timestamp = time.Now().UTC().Format(time.RFC3339)
	if machine := loadMachineConfig(t); machine != nil {
		rep.Machine = machine
	}
	blob, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		t.Logf("bench: marshal artifact: %v", err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		t.Logf("bench: mkdir %s: %v", filepath.Dir(out), err)
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(out), ".bench-*.json")
	if err != nil {
		t.Logf("bench: create temp artifact %s: %v", out, err)
		return
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(blob); err != nil {
		_ = tmp.Close()
		t.Logf("bench: write temp artifact %s: %v", tmpName, err)
		return
	}
	if err := tmp.Close(); err != nil {
		t.Logf("bench: close temp artifact %s: %v", tmpName, err)
		return
	}
	if err := os.Rename(tmpName, out); err != nil {
		t.Logf("bench: publish artifact %s: %v", out, err)
	}
}

// UC-94 — measure per-runtime create latency. For each runtime the scenario
// supports, create AEROL_BENCH_SAMPLES sandboxes serially, recording the
// Create() round-trip and the full create→running time, then report p50/p90/p99.
func TestBenchCreateLatency(t *testing.T) {
	harness.Require(t, sc, "UC-94")
	requireBenchEnabled(t)
	c := client(t)
	verifyNetrulesBackend(t, c)
	samples := benchEnvInt("AEROL_BENCH_SAMPLES", 10)
	runtimes := selectedBenchRuntimes(t)
	if len(runtimes) == 0 {
		t.Skip("no benchmark runtimes selected")
	}
	waitBenchmarkReady(t, c, runtimes)
	runtimes = prepareBenchmarkRuntimes(t, c, runtimes)
	warmBenchmarkRuntimes(t, c, runtimes)
	waitDockerPoolWarm(t, c, runtimes)

	var report benchReport
	for _, br := range runtimes {
		var apiD, runD, serverD []time.Duration
		stageD := map[string][]time.Duration{}
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
			// Per-stage breakdown from the same header (Phase 0 of
			// plans/firecracker-create-latency.md). Only stages the server
			// actually reported land here; docker creates carry the
			// runtime_wait/toolbox_wait pair, firecracker the fc_* set.
			if stages, ok := c.LastServerCreateStages(); ok {
				for name, ms := range stages {
					stageD[name] = append(stageD[name], time.Duration(ms*float64(time.Millisecond)))
				}
			}
		}

		if len(apiD) == 0 {
			t.Errorf("bench[%s]: every create sample failed", br.runtime)
			continue
		}
		ls := summarize(br.runtime, samples, failures, apiD, runD, serverD)
		ls.Stages = summarizeStages(stageD)
		report.Latency = append(report.Latency, ls)
		t.Logf("bench[%s] api p50=%dms p90=%dms p99=%dms | server p50=%dms p90=%dms p99=%dms | running p50=%dms p90=%dms p99=%dms (%d ok, %d fail)",
			br.runtime, ls.APIp50MS, ls.APIp90MS, ls.APIp99MS,
			ls.Serverp50MS, ls.Serverp90MS, ls.Serverp99MS,
			ls.Runp50MS, ls.Runp90MS, ls.Runp99MS, len(apiD), failures)
	}
	writeBenchArtifact(t, report)
}

// UC-94-sparse — same create latency sweep as UC-94, but with a long gap
// between samples so the image-ID TTL cache would go cold without the
// Client-owned warm loop (plans/warm-create-latency-tier1.md Phase 2).
// Gate: warm hits must not record docker_image (resolve) and warm server
// p50 must stay ≤ 30ms on the standard topology.
func TestBenchCreateLatencySparse(t *testing.T) {
	harness.Require(t, sc, "UC-94")
	requireBenchEnabled(t)
	if os.Getenv("AEROL_BENCH_SPARSE") != "1" {
		t.Skip("sparse benchmark disabled: set AEROL_BENCH_SPARSE=1 (one create per ≥15s)")
	}
	c := client(t)
	verifyNetrulesBackend(t, c)
	samples := benchEnvInt("AEROL_BENCH_SAMPLES", 10)
	gap := benchEnvDuration("AEROL_BENCH_SPARSE_GAP", 15*time.Second)
	runtimes := selectedBenchRuntimes(t)
	// Sparse gate is about the warm docker hit path.
	var dockerOnly []benchRuntimeSpec
	for _, br := range runtimes {
		if br.runtime == "docker" {
			dockerOnly = append(dockerOnly, br)
		}
	}
	if len(dockerOnly) == 0 {
		t.Skip("sparse bench requires docker runtime")
	}
	waitBenchmarkReady(t, c, dockerOnly)
	dockerOnly = prepareBenchmarkRuntimes(t, c, dockerOnly)
	warmBenchmarkRuntimes(t, c, dockerOnly)
	waitDockerPoolWarm(t, c, dockerOnly)

	var report benchReport
	for _, br := range dockerOnly {
		var apiD, runD, serverD []time.Duration
		stageD := map[string][]time.Duration{}
		failures := 0
		resolveHits := 0
		warmHits := 0
		for i := 0; i < samples; i++ {
			if i > 0 {
				t.Logf("sparse gap %s before sample %d", gap, i)
				time.Sleep(gap)
			}
			opts := benchCreateOptions(t, br)
			start := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			sb, err := c.SDK().Create(ctx, opts)
			apiElapsed := time.Since(start)
			cancel()
			if err != nil {
				failures++
				t.Logf("sparse[%s] sample %d create failed: %v", br.runtime, i, err)
				continue
			}
			id := sb.ID
			t.Cleanup(func() { destroyBest(c, id) })
			if waitRunningTimed(t, sb) {
				runD = append(runD, time.Since(start))
			} else {
				failures++
			}
			apiD = append(apiD, apiElapsed)
			if ms, ok := c.LastServerCreateMS(); ok {
				serverD = append(serverD, time.Duration(ms*float64(time.Millisecond)))
			}
			if stages, ok := c.LastServerCreateStages(); ok {
				for name, ms := range stages {
					stageD[name] = append(stageD[name], time.Duration(ms*float64(time.Millisecond)))
				}
				if _, hasPool := stages["docker_pool"]; hasPool {
					warmHits++
					if _, hasImg := stages["docker_image"]; hasImg {
						resolveHits++
					}
				}
			}
		}
		if len(apiD) == 0 {
			t.Errorf("sparse[%s]: every create sample failed", br.runtime)
			continue
		}
		ls := summarize(br.runtime+"-sparse", samples, failures, apiD, runD, serverD)
		ls.Stages = summarizeStages(stageD)
		report.Latency = append(report.Latency, ls)
		t.Logf("sparse[%s] server p50=%dms | warm_hits=%d resolve_on_warm=%d (%d ok, %d fail)",
			br.runtime, ls.Serverp50MS, warmHits, resolveHits, len(apiD), failures)
		// The gates below must not pass vacuously: a run with zero warm hits
		// or no Server-Timing data proves nothing about the warm path, which
		// is the entire point of the sparse sweep.
		if warmHits == 0 {
			t.Errorf("sparse gate: no warm pool hits across %d samples — pool drained or Server-Timing missing docker_pool", len(apiD))
		}
		if len(serverD) == 0 {
			t.Errorf("sparse gate: no Server-Timing create durations captured across %d samples", len(apiD))
		}
		// Allow a single resolve for a racey first sample; more than that
		// means the warm loop is not keeping the cache hot.
		if resolveHits > 1 {
			t.Errorf("sparse gate: docker_image resolve on %d/%d warm hits (want ~0)", resolveHits, warmHits)
		}
		if len(serverD) > 0 && ls.Serverp50MS > 30 {
			t.Errorf("sparse gate: warm server p50=%dms want ≤30ms", ls.Serverp50MS)
		}
	}
	writeBenchArtifact(t, report)
}

func benchEnvDuration(key string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
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

// summarizeStages folds the per-stage samples into the artifact's
// latency[].stages block. Nil when the server reported no stages.
func summarizeStages(stageD map[string][]time.Duration) map[string]stageStats {
	if len(stageD) == 0 {
		return nil
	}
	out := make(map[string]stageStats, len(stageD))
	for name, durs := range stageD {
		if len(durs) == 0 {
			continue
		}
		out[name] = stageStats{
			Samples: len(durs),
			MeanMS:  meanMS(durs),
			P50MS:   percentile(durs, 50).Milliseconds(),
		}
	}
	return out
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
//
// On a containerd-engine scenario the "docker" runtime is served by the native
// containerd driver (a containerd node advertises "docker" in
// supported_runtimes), so the creates are genuinely containerd creates and the
// ceiling measures containerd fleet density — we relabel the row "containerd"
// so the artifact is self-documenting. Admission is capacity-based (CPU/mem
// reservations), so the ceiling is engine-independent by design; the row still
// gives an apples-to-apples density number next to the docker baseline.
func TestBenchDensity(t *testing.T) {
	harness.Require(t, sc, "UC-95")
	requireBenchEnabled(t)
	if !benchRuntimeAllowed("docker") && !benchRuntimeAllowed("containerd") {
		t.Skip("AEROL_BENCH_RUNTIMES excludes docker and containerd; density probe needs one of them")
	}
	c := client(t)
	dockerBench := []benchRuntimeSpec{{runtime: "docker"}}
	waitBenchmarkReady(t, c, dockerBench)
	warmBenchmarkRuntimes(t, c, dockerBench)
	maxSandboxes := benchEnvInt("AEROL_BENCH_MAX", 200)

	// The create runtime stays "docker" (what every node advertises); the label
	// reflects the host engine so a containerd run reads as containerd density.
	densityRuntime := "docker"
	if sc.Has(harness.CapContainerdEngine) {
		densityRuntime = "containerd"
	}
	ds := densityStats{Runtime: densityRuntime}
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
			if isDensityCeiling(err) {
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

// isDensityCeiling reports whether err is the fleet refusing more sandboxes —
// either explicit capacity admission (HTTP 503 `capacity exceeded`) or cluster
// placement exhaustion (`no worker placement target available`). Both are valid
// UC-95 stop conditions: the probe measures how many sandboxes land before the
// fleet stops accepting more.
func isDensityCeiling(err error) bool {
	if isCapacityRejection(err) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no worker placement target")
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
