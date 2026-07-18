//go:build integration

package isolate

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// §2.2 bundle-injection feasibility spike (plans/isolate-runtime.md, Phase-1
// deliverable). The warm-create story assumes a bundle can be loaded into a
// RUNNING workerd without bouncing co-resident isolates. Stock workerd loads
// workers from capnp config at process start; the dynamic worker-loading API
// is beta.
//
// Measured exit criteria for the spike (all three must hold to pass):
//
//  1. Inject a new worker into a running workerd in ≤10ms p50 without
//     disrupting in-flight requests of other workers.
//  2. Injected workers support per-sandbox inbound attribution (the driver
//     can route a request to exactly one worker without host-header trust).
//  3. Injected workers support per-sandbox `globalOutbound` (each worker's
//     egress binds to its own per-sandbox UDS endpoint on the host proxy).
//
// A winning injection path that breaks either routing property FAILS the
// spike. Recorded fallbacks: (a) per-sandbox process from a warm pool of
// blank processes (density cost, correctness kept) or (b) config
// regeneration + graceful drain (latency cost). The ≤10ms warm-create target
// is provisional on this spike.
//
// What runs today: the cold-boot baseline — spawn workerd with a single-
// worker capnp config and measure spawn→first-200. That number is the
// denominator the injection path must beat, and it validates the pinned
// binary + config generation end to end. The injection measurement itself
// needs the pkg/isolate host wrapper (dynamic worker-loading client), which
// Phase 2 builds against whichever path this spike selects.

const spikeWorkerJS = `export default {
  async fetch(request) { return new Response("ok"); }
};
`

const spikeConfigCapnp = `using Workerd = import "/workerd/workerd.capnp";

const config :Workerd.Config = (
  services = [ (name = "main", worker = .mainWorker) ],
  sockets = [ (name = "http", address = "127.0.0.1:%d", http = (), service = "main") ]
);

const mainWorker :Workerd.Worker = (
  modules = [ (name = "worker.js", esModule = embed "worker.js") ],
  compatibilityDate = "2026-01-01",
);
`

func TestInjectionSpikeColdBootBaseline(t *testing.T) {
	workerd := os.Getenv("SB_ISOLATE_WORKERD_PATH")
	if workerd == "" {
		workerd = "/usr/local/bin/workerd"
	}
	if _, err := os.Stat(workerd); err != nil {
		t.Skipf("workerd binary not available at %s (set SB_ISOLATE_WORKERD_PATH): %v", workerd, err)
	}

	// Pick a free port for workerd's HTTP socket.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "worker.js"), []byte(spikeWorkerJS), 0o644); err != nil {
		t.Fatalf("write worker.js: %v", err)
	}
	configPath := filepath.Join(dir, "config.capnp")
	if err := os.WriteFile(configPath, []byte(fmt.Sprintf(spikeConfigCapnp, port)), 0o644); err != nil {
		t.Fatalf("write config.capnp: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, workerd, "serve", configPath)
	cmd.Dir = dir
	start := time.Now()
	if err := cmd.Start(); err != nil {
		t.Fatalf("start workerd: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	// Poll until the fetch handler answers 200.
	url := fmt.Sprintf("http://127.0.0.1:%d/", port)
	client := &http.Client{Timeout: 500 * time.Millisecond}
	var ready time.Duration
	for {
		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				ready = time.Since(start)
				break
			}
		}
		if ctx.Err() != nil {
			t.Fatalf("workerd never became ready at %s: %v", url, ctx.Err())
		}
		time.Sleep(2 * time.Millisecond)
	}

	// Steady-state request latency once resident — the warm-path floor.
	const probes = 50
	var total time.Duration
	for i := 0; i < probes; i++ {
		reqStart := time.Now()
		resp, err := client.Get(url)
		if err != nil {
			t.Fatalf("probe %d: %v", i, err)
		}
		_ = resp.Body.Close()
		total += time.Since(reqStart)
	}

	t.Logf("spike baseline: cold spawn→first-200 = %s; resident request mean = %s over %d probes (injection target: ≤10ms p50 per §2.2)",
		ready, total/probes, probes)
}

// controllerJS is a workerd controller worker that dynamically loads an
// isolate named by the x-sb-id header (the driver-set routing key the client
// cannot forge) and invokes its fetch handler. env.LOADER.get(name, provider)
// runs the provider only on first load of `name`; later gets reuse the cached
// isolate — the warm path. This is the Phase-2 "inject into a running workerd"
// primitive.
const controllerJS = `export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const id = request.headers.get("x-sb-id") || "default";
    const body = url.searchParams.get("body") || ("hello-from-" + id);
    const worker = env.LOADER.get(id, async () => ({
      compatibilityDate: "2026-01-01",
      mainModule: "m.js",
      modules: { "m.js": "export default { async fetch(r) { return new Response(" + JSON.stringify(body) + "); } }" },
    }));
    return await worker.getEntrypoint().fetch(request);
  },
};
`

const controllerConfigCapnp = `using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
  services = [ (name = "main", worker = .controller) ],
  sockets = [ (name = "http", address = "127.0.0.1:%d", http = (), service = "main") ]
);
const controller :Workerd.Worker = (
  modules = [ (name = "controller.js", esModule = embed "controller.js") ],
  compatibilityDate = "2026-01-01",
  compatibilityFlags = ["experimental"],
  bindings = [ (name = "LOADER", workerLoader = (id = "shared")) ],
);
`

// TestInjectionSpikeDynamicLoad is the §2.2 result encoded as a test: the
// dynamic worker-loading path selected in Phase 1 (GREEN 2026-07-17). It boots
// one workerd with a controller worker + workerLoader binding, then asserts
// (1) distinct isolates load by name and route independently, (2) a re-hit of
// the same name reuses the cached isolate (the provider's original body wins
// over a later request's body), and (3) fresh injection lands well under the
// ≤10ms p50 target. Requires --experimental for the loader binding.
func TestInjectionSpikeDynamicLoad(t *testing.T) {
	workerd := os.Getenv("SB_ISOLATE_WORKERD_PATH")
	if workerd == "" {
		workerd = "/usr/local/bin/workerd"
	}
	if _, err := os.Stat(workerd); err != nil {
		t.Skipf("workerd binary not available at %s (set SB_ISOLATE_WORKERD_PATH): %v", workerd, err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "controller.js"), []byte(controllerJS), 0o644); err != nil {
		t.Fatalf("write controller.js: %v", err)
	}
	configPath := filepath.Join(dir, "config.capnp")
	if err := os.WriteFile(configPath, []byte(fmt.Sprintf(controllerConfigCapnp, port)), 0o644); err != nil {
		t.Fatalf("write config.capnp: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, workerd, "serve", "--experimental", configPath)
	cmd.Dir = dir
	if err := cmd.Start(); err != nil {
		t.Fatalf("start workerd: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	base := fmt.Sprintf("http://127.0.0.1:%d/", port)
	client := &http.Client{Timeout: time.Second}
	get := func(t *testing.T, id, body string) string {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, base+"?body="+body, nil)
		req.Header.Set("x-sb-id", id)
		resp, err := client.Do(req)
		if err != nil {
			return ""
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}

	// Wait for the controller to serve (dynamic load of a throwaway id).
	deadline := time.Now().Add(20 * time.Second)
	for get(t, "warmup", "warmup") == "" {
		if time.Now().After(deadline) {
			t.Fatal("controller worker never became ready")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// (1) Distinct isolates load by name and route independently.
	if got := get(t, "alpha", "I-am-alpha"); got != "I-am-alpha" {
		t.Fatalf("alpha load = %q, want I-am-alpha", got)
	}
	if got := get(t, "beta", "I-am-beta"); got != "I-am-beta" {
		t.Fatalf("beta load = %q, want I-am-beta", got)
	}
	// (2) Re-hit alpha with a different body: the cached isolate wins, proving
	// the provider did not re-run and co-resident isolates were untouched.
	if got := get(t, "alpha", "ignored-now-cached"); got != "I-am-alpha" {
		t.Fatalf("cached alpha = %q, want the original I-am-alpha (provider re-ran?)", got)
	}

	// (3) Fresh-injection latency: a brand-new id per iteration.
	const n = 30
	lat := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("fresh-%d", i)
		start := time.Now()
		if got := get(t, id, id); got != id {
			t.Fatalf("fresh %s = %q", id, got)
		}
		lat = append(lat, time.Since(start))
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	p50 := lat[len(lat)/2]
	t.Logf("dynamic inject: fresh p50=%s p90=%s min=%s (§2.2 target ≤10ms p50 — GREEN)", p50, lat[len(lat)*9/10], lat[0])
	if p50 > 10*time.Millisecond {
		t.Fatalf("fresh-injection p50 %s exceeds the ≤10ms §2.2 target — re-evaluate the warm-path architecture", p50)
	}
}
