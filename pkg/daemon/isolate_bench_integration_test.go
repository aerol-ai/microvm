//go:build integration

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/api"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestIsolateOfflineBenchmark is the OFFLINE analogue of the live cluster
// create-latency bench (integration-tests/suite/benchmark_test.go). It stands
// up the real HTTP API server in-process — store + service + isolate driver +
// a real workerd binary — so a create traverses the full HTTP → auth →
// service → group router → workerd inject path with no docker, no caddy, no
// AWS. It measures wall-clock per POST /v1/sandboxes and reports cold (first,
// pays the group-process spawn) separately from warm (subsequent, inject into
// the resident group).
//
// Tag-gated (needs a real workerd via SB_ISOLATE_WORKERD_PATH). Sample count
// is AEROL_BENCH_SAMPLES (default 30). This is the offline number to quote for
// the isolate runtime's server-side create latency.
func TestIsolateOfflineBenchmark(t *testing.T) {
	workerd := os.Getenv("SB_ISOLATE_WORKERD_PATH")
	if workerd == "" {
		workerd = "/usr/local/bin/workerd"
	}
	if _, err := os.Stat(workerd); err != nil {
		t.Skipf("workerd not available at %s (set SB_ISOLATE_WORKERD_PATH): %v", workerd, err)
	}

	// macOS unix-socket sun_path is 104 chars; the per-group control/host/egress
	// sockets live under RunDir/<groupKey>, so keep the root short.
	runDir, err := os.MkdirTemp("/tmp", "isobench")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(runDir) })

	db, err := store.Open(filepath.Join(t.TempDir(), "bench.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	cfg := config.Config{
		EnableIsolate:           true,
		IsolateWorkerdPath:      workerd,
		IsolateRunDir:           runDir,
		IsolateGroupGranularity: config.IsolateGroupPerTenant,
		IsolateUseJail:          false, // no chroot/seccomp on darwin; Phase 2 jail is spec-only
		// The jail SPEC is always built + validated (only realization is gated
		// by UseJail), so a valid absolute chroot base is required even off.
		IsolateJailChrootBase: filepath.Join(runDir, "jail"),
		IsolateJailUID:        1000,
		IsolateJailGID:        1000,
	}

	// Admit isolate + docker (docker is the always-present host default). A
	// generous fake host budget so admission never rejects during the bench.
	admitter := capacity.New(capacity.HostInfo{
		CPUCores:          runtime.NumCPU(),
		MemoryTotalMB:     32768,
		SupportedRuntimes: []string{models.RuntimeDocker, models.RuntimeIsolate},
	}, capacity.Limits{}, benchMemProbe{freeMB: 32768})

	logger := slog.New(slog.NewTextHandler(io.Discard, nil)) // quiet: bench noise off
	svc := service.New(cfg, logger, db, nil, nil, nil, nil, nil, admitter)

	// Wire the isolate driver + bundle store exactly as the daemon does. Keep
	// the driver handle so the cleanup can tear down the workerd group
	// processes — leaving them resident makes `go test` block on their open
	// stdio pipes (WaitDelay) even after the test body passes.
	driver, err := wireIsolateRuntime(cfg, logger, svc)
	if err != nil {
		t.Fatalf("wire isolate runtime: %v", err)
	}
	var createdIDs []string
	t.Cleanup(func() {
		for _, id := range createdIDs {
			_ = driver.Destroy(context.Background(), &models.Sandbox{ID: id})
		}
	})

	const pat = "bench-operator-pat"
	srv := api.NewServer(logger, svc, nil, nil, cfg, pat, nil)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	client := ts.Client()
	do := func(method, path string, body any) (*http.Response, []byte) {
		t.Helper()
		var rdr io.Reader
		if body != nil {
			raw, _ := json.Marshal(body)
			rdr = bytes.NewReader(raw)
		}
		req, err := http.NewRequest(method, ts.URL+path, rdr)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+pat)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		return resp, out
	}

	// Upload the bundle every create references by name. A trivial fetch
	// handler keeps the measurement on the platform path, not user JS.
	const workerSrc = `export default { async fetch(req) { return new Response("ok"); } };`
	resp, out := do(http.MethodPost, "/v1/js-bundles", models.CreateJSBundleRequest{
		Name:   "bench",
		Source: workerSrc,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("upload bundle: status %d body %s", resp.StatusCode, out)
	}
	var bundle models.JSBundle
	if err := json.Unmarshal(out, &bundle); err != nil {
		t.Fatalf("decode bundle: %v (body %s)", err, out)
	}
	t.Logf("bundle uploaded: %s (%d bytes)", bundle.ModuleRef, bundle.SizeBytes)

	samples := 30
	if v := os.Getenv("AEROL_BENCH_SAMPLES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			samples = n
		}
	}

	createOne := func(i int) time.Duration {
		start := time.Now()
		resp, out := do(http.MethodPost, "/v1/sandboxes", models.CreateSandboxRequest{
			Runtime:   models.RuntimeIsolate,
			ModuleRef: "bench",
			TenantID:  "acme", // one shared group process across all samples
			MemoryMB:  128,
		})
		d := time.Since(start)
		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
			t.Fatalf("create %d: status %d body %s", i, resp.StatusCode, out)
		}
		var cr models.CreateSandboxResponse
		if err := json.Unmarshal(out, &cr); err == nil && cr.Sandbox.ID != "" {
			createdIDs = append(createdIDs, cr.Sandbox.ID)
		}
		return d
	}

	// Cold: first create pays the workerd group-process spawn + controller
	// bring-up. All later creates inject into the resident group.
	cold := createOne(0)
	t.Logf("cold create (group spawn): %s", cold)

	warm := make([]time.Duration, 0, samples)
	for i := 1; i <= samples; i++ {
		warm = append(warm, createOne(i))
	}

	p := func(ds []time.Duration, q float64) time.Duration {
		if len(ds) == 0 {
			return 0
		}
		s := append([]time.Duration(nil), ds...)
		sort.Slice(s, func(a, b int) bool { return s[a] < s[b] })
		idx := int(q * float64(len(s)-1))
		return s[idx]
	}
	ms := func(d time.Duration) string { return fmt.Sprintf("%.1fms", float64(d.Microseconds())/1000) }

	t.Logf("=== isolate offline bench (%d warm samples, in-process HTTP server, real workerd) ===", len(warm))
	t.Logf("cold (group spawn) : %s", ms(cold))
	t.Logf("warm p50 : %s", ms(p(warm, 0.50)))
	t.Logf("warm p90 : %s", ms(p(warm, 0.90)))
	t.Logf("warm p99 : %s", ms(p(warm, 0.99)))
	t.Logf("warm min : %s  max : %s", ms(p(warm, 0)), ms(p(warm, 1)))

	// One resident group process serves every sample (per-tenant granularity).
	list, out := do(http.MethodGet, "/v1/sandboxes", nil)
	if list.StatusCode != http.StatusOK {
		t.Fatalf("list: status %d body %s", list.StatusCode, out)
	}
	var sandboxes []models.Sandbox
	_ = json.Unmarshal(out, &sandboxes)
	created := 0
	for _, sb := range sandboxes {
		if sb.Runtime == models.RuntimeIsolate {
			created++
		}
	}
	if created != samples+1 {
		t.Fatalf("created %d isolate sandboxes, want %d", created, samples+1)
	}
}

// benchMemProbe is a fixed-free MemProbe so the bench never depends on
// /proc/meminfo (absent on darwin). With Limits{} the floor check is off, so
// this is belt-and-suspenders.
type benchMemProbe struct{ freeMB int }

func (b benchMemProbe) FreeMB() (int, error) { return b.freeMB, nil }
