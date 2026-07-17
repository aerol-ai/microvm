//go:build integration

package isolate

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
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
