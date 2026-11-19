//go:build wasmbench

// Package wasmbench_test measures WASM create latency with real workers:
//
//	(i)   resident host, first create for a new owner, another owner having
//	      compiled the module on this node
//	(ii)  a second create in the same resident bucket
//	(iii) a warm-pool hit, resident host off
//	(iv)  cold: an empty compile cache, resident host on
//
// It is behind the wasmbench tag (make test never runs it) and needs Linux
// root in a container that allows new PID namespaces when workers drop:
//
//	go test -tags wasmbench -run TestCreateLatency -v ./internal/runtime/wasm/wasmbench
//
// BENCH_RUNS sets the runs per case (default 20), BENCH_OUT a JSON file for
// the results, and BENCH_ONLY=i stops after (i) and prints the driver's
// create stages. To compare with another tree, copy this folder there and
// rewrite setup_test.go for that tree: it is the only file that differs,
// so the numbers compare.
package wasmbench_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	wasmpool "github.com/aerol-ai/microvm/internal/pool/wasm"
	"github.com/aerol-ai/microvm/internal/runtime/wasm"
	"github.com/aerol-ai/microvm/internal/wasmtestguest"
	"github.com/aerol-ai/microvm/pkg/createtiming"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/wasm/worker"
	"github.com/aerol-ai/microvm/pkg/wasmmod"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		var err error
		handled := true
		switch os.Args[1] {
		case worker.WorkerFlag:
			err = worker.RunCLI(os.Args[2:])
		case worker.ResidentHostFlag:
			err = worker.RunCLIResident(os.Args[2:])
		default:
			handled, err = dispatchExtra(os.Args)
		}
		if handled {
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			os.Exit(0)
		}
	}
	os.Exit(m.Run())
}

type env struct {
	driver    *wasm.Driver
	workers   *worker.Supervisor
	runDir    string
	modules   string
	cacheRoot string
}

func newEnv(t *testing.T, base, cacheRoot string, resident bool) *env {
	t.Helper()
	e := &env{
		runDir:    filepath.Join(base, "run"),
		modules:   filepath.Join(base, "modules"),
		cacheRoot: cacheRoot,
	}
	for _, d := range []string{e.runDir, e.modules} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(wasmtestguest.Path(t, wasmtestguest.Stdio))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.modules, "aerolstdio.wasm"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	resolver := wasmmod.NewModuleResolver(e.modules, "")
	resolver.Reserved = map[string]string{"stdio": "aerolstdio.wasm"}
	cfg := wasm.Config{
		RunDir:                   e.runDir,
		ModulesDir:               e.modules,
		DefaultMemoryMB:          64,
		DefaultWallTimeout:       30 * time.Second,
		ResidentHostEnabled:      resident,
		ResidentHostMaxInstances: 64,
	}
	e.driver, e.workers = newBenchDriver(t, cfg, e, resolver)
	e.driver.SetModuleResolver(resolver)
	return e
}

func (e *env) create(t *testing.T, owner, id string) time.Duration {
	t.Helper()
	ctx, tm := createtiming.With(wasmmod.WithCatalogueOwner(context.Background(), owner))
	start := time.Now()
	if _, err := e.driver.Create(ctx, models.CreateSandboxRequest{Image: "stdio"}, id, "tok", nil); err != nil {
		t.Fatalf("create %s: %v", id, err)
	}
	took := time.Since(start)
	for _, st := range tm.Stages() {
		stageLog[st.Name] = append(stageLog[st.Name], st.DurMS)
	}
	dstart := time.Now()
	if err := e.driver.Destroy(context.Background(), &models.Sandbox{ID: id}); err != nil {
		t.Fatalf("destroy %s: %v", id, err)
	}
	stageLog["bench_destroy"] = append(stageLog["bench_destroy"], float64(time.Since(dstart).Microseconds())/1000)
	return took
}

var stageLog = map[string][]float64{}

type result struct {
	Scenario string    `json:"scenario"`
	Runs     int       `json:"runs"`
	P50ms    float64   `json:"p50_ms"`
	P95ms    float64   `json:"p95_ms"`
	All      []float64 `json:"all_ms"`
}

func summarize(name string, ds []time.Duration) result {
	ms := make([]float64, len(ds))
	for i, d := range ds {
		ms[i] = float64(d.Microseconds()) / 1000
	}
	sorted := append([]float64(nil), ms...)
	sort.Float64s(sorted)
	pick := func(q float64) float64 { return sorted[int(q*float64(len(sorted)-1)+0.5)] }
	return result{Scenario: name, Runs: len(ms), P50ms: pick(0.5), P95ms: pick(0.95), All: ms}
}

func TestCreateLatency(t *testing.T) {
	runs := 20
	if v, err := strconv.Atoi(os.Getenv("BENCH_RUNS")); err == nil && v > 0 {
		runs = v
	}
	var results []result
	t.Cleanup(killChildren)

	// (i) and (ii): one node, resident host on.
	node := newEnv(t, t.TempDir(), filepath.Join(t.TempDir(), "cache"), true)
	node.create(t, "seed-owner", "sb-seed") // another owner compiles it first
	var first, second []time.Duration
	for k := range runs {
		first = append(first, node.create(t, fmt.Sprintf("new-owner-%d", k), fmt.Sprintf("sb-i-%d", k)))
	}
	for k := range runs {
		second = append(second, node.create(t, "new-owner-0", fmt.Sprintf("sb-ii-%d", k)))
	}
	results = append(results, summarize("i_resident_new_owner", first), summarize("ii_resident_same_bucket", second))
	if os.Getenv("BENCH_ONLY") == "i" {
		for _, r := range results[:1] {
			t.Logf("%-26s runs=%d p50=%.1fms p95=%.1fms", r.Scenario, r.Runs, r.P50ms, r.P95ms)
		}
		names := make([]string, 0, len(stageLog))
		for n := range stageLog {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			v := append([]float64(nil), stageLog[n]...)
			sort.Float64s(v)
			t.Logf("  stage %-22s n=%d p50=%.2fms p95=%.2fms", n, len(v), v[len(v)/2], v[int(0.95*float64(len(v)-1)+0.5)])
		}
		return
	}

	// (iii): resident host off, a warm slot ready before each create.
	warmNode := newEnv(t, t.TempDir(), filepath.Join(t.TempDir(), "cache"), false)
	pool := wasmpool.New(warmNode.runDir, nil)
	pool.SetSpawner(newPoolSpawner(warmNode))
	pool.SetDefaultMemoryMB(64)
	warmNode.driver.SetWarmPool(pool)
	resolved, err := wasmmod.NewModuleResolver(warmNode.modules, "").Resolve(context.Background(), "aerolstdio.wasm")
	if err != nil {
		t.Fatal(err)
	}
	pool.NoteModule(resolved.Digest, resolved.Path)
	bootNode(warmNode)
	var warm, refill []time.Duration
	for k := range runs {
		wstart := time.Now()
		slot, err := pool.WarmOne(context.Background(), resolved.Digest, resolved.Path)
		if err != nil {
			t.Fatalf("warm: %v", err)
		}
		refill = append(refill, time.Since(wstart))
		pool.RecordLoaded(slot)
		warm = append(warm, warmNode.create(t, "warm-owner", fmt.Sprintf("sb-iii-%d", k)))
	}
	results = append(results, summarize("iii_warm_pool_hit", warm), summarize("iii_refill_one_slot", refill))

	// (iv): a fresh node each time, nothing compiled.
	var cold []time.Duration
	for k := range runs {
		fresh := newEnv(t, t.TempDir(), filepath.Join(t.TempDir(), "cache"), true)
		cold = append(cold, fresh.create(t, "cold-owner", fmt.Sprintf("sb-iv-%d", k)))
	}
	results = append(results, summarize("iv_cold_empty_cache", cold))

	for _, r := range results {
		t.Logf("%-26s runs=%d p50=%.1fms p95=%.1fms", r.Scenario, r.Runs, r.P50ms, r.P95ms)
	}
	if out := os.Getenv("BENCH_OUT"); out != "" {
		raw, _ := json.MarshalIndent(results, "", "  ")
		if err := os.WriteFile(out, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// killChildren ends the workers this test started (resident hosts outlive
// their sandboxes): they write to the test's own output.
func killChildren() {
	self := strconv.Itoa(os.Getpid())
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		if err != nil {
			continue
		}
		fields := strings.Fields(string(raw[strings.LastIndexByte(string(raw), ')')+1:]))
		if len(fields) > 1 && fields[1] == self {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
}
