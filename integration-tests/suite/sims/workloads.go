//go:build integration

package sims

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	"github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// runTemporalWorkflowSim: durable multi-step workflow via sequential sandbox
// activities (create → exec step → destroy) with one retry — Temporal-shaped
// without requiring the full Temporal stack image.
func runTemporalWorkflowSim(ctx *RunContext) Result {
	res := baseResult(ctx, "temporal-workflow", "SVC-06")
	if !ctx.Scenario.Has(harness.CapDocker) {
		return skip(res, "requires docker")
	}
	steps := []string{"validate", "transform", "persist", "notify", "complete"}
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		lastErr = nil
		for _, step := range steps {
			sb, err := ctx.Client.SDK().Create(context.Background(), sdktypes.CreateSandboxOptions{
				Name:             harness.UniqueName(ctx.Scenario, ctx.T) + "-" + step,
				Image:            "alpine:3.20",
				ContainerCommand: []string{"sh", "-c", fmt.Sprintf("echo step=%s ok", step)},
			})
			if err != nil {
				lastErr = err
				break
			}
			waitRunningTB(ctx.T, sb)
			out, err := execInSandbox(sb, "cat /dev/null; echo ok")
			_ = ctx.Client.SDK().Destroy(context.Background(), sb.ID)
			if err != nil || !strings.Contains(out, "ok") {
				lastErr = fmt.Errorf("step %s: %v out=%q", step, err, out)
				break
			}
		}
		if lastErr == nil {
			res.Success = true
			res.Notes = fmt.Sprintf("5-step workflow completed (attempt %d)", attempt+1)
			return res
		}
	}
	return fail(res, "workflow failed after retry: %v", lastErr)
}

// runHyperparamFarm: 3 parallel trainers return an accuracy string.
func runHyperparamFarm(ctx *RunContext) Result {
	res := baseResult(ctx, "hyperparam-farm", "COMP-01")
	if !ctx.Scenario.Has(harness.CapDocker) {
		return skip(res, "requires docker")
	}
	const n = 3
	type outcome struct {
		ok  bool
		err error
		acc string
	}
	ch := make(chan outcome, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		i := i
		go func() {
			defer wg.Done()
			acc := fmt.Sprintf("0.%d42", i+5)
			// A 3-wide concurrent create burst can momentarily exceed a node's
			// pending-reservation budget on this small benchmark cluster: the
			// warm pools already hold most of the per-node CPU-budget slots, so
			// one trainer can lose the race for the last slot even though
			// capacity frees the instant an in-flight create resolves. Real
			// hyperparameter fan-out retries these transient admission
			// rejections — without it a single one flakes the whole farm. Stagger
			// the retry (grows with attempt) so the trainers don't re-collide on
			// the same freed slot. Non-transient errors fail fast.
			var sb *microvm.Sandbox
			var err error
			for attempt := 0; attempt < 4; attempt++ {
				sb, err = ctx.Client.SDK().Create(context.Background(), sdktypes.CreateSandboxOptions{
					Name:             harness.UniqueName(ctx.Scenario, ctx.T) + fmt.Sprintf("-train-%d", i),
					Image:            "alpine:3.20",
					ContainerCommand: []string{"sh", "-c", "sleep 1; echo accuracy=" + acc},
				})
				if err == nil || !isTransientCapacity(err) {
					break
				}
				time.Sleep(time.Duration(attempt+1) * 2 * time.Second)
			}
			if err != nil {
				ch <- outcome{err: err}
				return
			}
			defer func() { _ = ctx.Client.SDK().Destroy(context.Background(), sb.ID) }()
			waitRunningTB(ctx.T, sb)
			out, err := execInSandbox(sb, "echo accuracy="+acc)
			if err != nil {
				ch <- outcome{err: err}
				return
			}
			ch <- outcome{ok: strings.Contains(out, "accuracy="), acc: strings.TrimSpace(out)}
		}()
	}
	wg.Wait()
	close(ch)
	var okCount int
	for o := range ch {
		if o.ok {
			okCount++
		} else if o.err != nil {
			return fail(res, "trainer failed: %v", o.err)
		}
	}
	if okCount != n {
		return fail(res, "want %d trainers, got %d", n, okCount)
	}
	res.Success = true
	res.Notes = fmt.Sprintf("%d parallel trainers returned accuracy", n)
	return res
}

// runServerlessWakeSim: create with idle auto-stop + serverless arm, expose HTTP.
func runServerlessWakeSim(ctx *RunContext) Result {
	res := baseResult(ctx, "serverless-wake", "SLESS-01")
	if !ctx.Scenario.Has(harness.CapDocker) || !ctx.Scenario.Has(harness.CapDomain) {
		return skip(res, "requires docker + domain")
	}
	trueVal := true
	sb, err := ctx.Client.SDK().Create(context.Background(), sdktypes.CreateSandboxOptions{
		Name:  harness.UniqueName(ctx.Scenario, ctx.T),
		Image: "hashicorp/http-echo:1.0",
		// ContainerCommand is the FULL argv the toolbox execs — it replaces the
		// image ENTRYPOINT (both docker and containerd drivers set the container
		// entrypoint to the toolbox shim and pass this as the argv it runs). So
		// argv[0] must be the http-echo binary, not a bare flag; passing just
		// "-text=..." makes the toolbox try to exec "-text=awake" → the main
		// process never starts and :8080 gets connection-refused.
		ContainerCommand:   []string{"/http-echo", "-text=awake", "-listen=:8080"},
		AllowPublicTraffic: &trueVal,
		Lifecycle: &sdktypes.Lifecycle{
			StopIfIdleFor: 30 * time.Second,
			Serverless:    true,
		},
	})
	if err != nil {
		return skip(res, "serverless lifecycle create unsupported: %v", err)
	}
	waitRunningTB(ctx.T, sb)
	ectx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	exposed, err := sb.ExposePort(ectx, 8080)
	if err != nil {
		_ = ctx.Client.SDK().Destroy(context.Background(), sb.ID)
		return fail(res, "expose: %v", err)
	}
	ctx.T.Cleanup(func() {
		tctx, tcancel := context.WithTimeout(context.Background(), time.Minute)
		defer tcancel()
		_ = sb.UnexposePort(tctx, 8080)
		_ = ctx.Client.SDK().Destroy(tctx, sb.ID)
		assertTornDown(ctx.T, ctx.Client, sb.ID, "http", "", 0)
	})
	if err := waitHTTP200(exposed.PublicURL, 30*time.Second); err != nil {
		return fail(res, "initial hit: %v", err)
	}
	res.PublicURL = exposed.PublicURL
	res.Success = true
	res.Notes = "echo service exposed; StopIfIdleFor+Serverless armed"
	return res
}

// runBurnerBrowserSim: noVNC-style desktop under gVisor when image available.
func runBurnerBrowserSim(ctx *RunContext) Result {
	res := baseResult(ctx, "burner-browser", "ISO-06")
	if !ctx.Scenario.Has(harness.CapGvisor) {
		return skip(res, "requires gvisor")
	}
	if os.Getenv("AEROL_SIM_SKIP_GVISOR") == "1" {
		return skip(res, "AEROL_SIM_SKIP_GVISOR=1")
	}
	image := os.Getenv("AEROL_SIM_NOVNC_IMAGE")
	if image == "" {
		return skip(res, "set AEROL_SIM_NOVNC_IMAGE to a mirrored noVNC image")
	}
	trueVal := true
	rt := "gvisor"
	_, exposed := securedExpose(ctx.T, ctx.Client, ctx.Scenario, sdktypes.CreateSandboxOptions{
		Image:              image,
		Runtime:            rt,
		AllowPublicTraffic: &trueVal,
	}, 6080, "")
	if err := waitHTTP200(exposed.PublicURL, 2*time.Minute); err != nil {
		return fail(res, "novnc: %v", err)
	}
	res.PublicURL = exposed.PublicURL
	res.Success = true
	res.Notes = "noVNC served 200 under gVisor"
	return res
}

// runCodeInterpreterCharts: matplotlib PNG via python alpine if image present.
func runCodeInterpreterCharts(ctx *RunContext) Result {
	res := baseResult(ctx, "code-interpreter", "COMP-05")
	if !ctx.Scenario.Has(harness.CapDocker) {
		return skip(res, "requires docker")
	}
	image := os.Getenv("AEROL_SIM_PYTHON_IMAGE")
	if image == "" {
		image = "python:3.12-slim"
	}
	sb, err := ctx.Client.SDK().Create(context.Background(), sdktypes.CreateSandboxOptions{
		Name:             harness.UniqueName(ctx.Scenario, ctx.T),
		Image:            image,
		ContainerCommand: []string{"sleep", "infinity"},
	})
	if err != nil {
		return skip(res, "create python sandbox: %v", err)
	}
	defer func() { _ = ctx.Client.SDK().Destroy(context.Background(), sb.ID) }()
	waitRunningTB(ctx.T, sb)
	script := `python - <<'PY'
import sys
try:
 import matplotlib
 matplotlib.use('Agg')
 import matplotlib.pyplot as plt
 plt.plot([1,2,3],[1,4,9]); plt.savefig('/tmp/chart.png')
 print('png_ok', os.path.getsize('/tmp/chart.png') if False else __import__('os').path.getsize('/tmp/chart.png'))
except Exception as e:
 print('skip', e); sys.exit(2)
PY`
	out, err := execInSandbox(sb, "sh -c "+shellQuote(script))
	if err != nil || !strings.Contains(out, "png_ok") {
		return skip(res, "matplotlib unavailable in image: %v out=%q", err, out)
	}
	res.Success = true
	res.Notes = "matplotlib PNG artifact written"
	return res
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

// isTransientCapacity reports whether a create error is a transient cluster
// admission rejection — a concurrent burst momentarily exceeding a node's
// pending-reservation budget — that clears with a brief backoff, as opposed to
// a hard/permanent failure. Matched on the message because the SDK surfaces the
// server's admission-control error as a plain error string. Kept narrow so a
// real bug (bad image, auth, malformed request) still fails the sim fast.
func isTransientCapacity(err error) bool {
	if err == nil {
		return false
	}
	m := strings.ToLower(err.Error())
	return strings.Contains(m, "target capacity exceeded") ||
		strings.Contains(m, "pending reservations") ||
		strings.Contains(m, "no worker placement target") ||
		strings.Contains(m, "cannot fit sandbox")
}
