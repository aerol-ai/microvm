//go:build integration

package sims

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	"github.com/aerol-ai/microvm/pkg/models"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

func runPostgresSupabase(ctx *RunContext) Result {
	res := baseResult(ctx, "postgres-supabase", "SVC-01")
	if !ctx.Scenario.Has(harness.CapDocker) || !ctx.Scenario.Has(harness.CapDomain) {
		return skip(res, "requires docker + domain for TLS-SNI expose")
	}
	const password = "itest-pg-pass"
	sb, exposed := securedExpose(ctx.T, ctx.Client, ctx.Scenario, sdktypes.CreateSandboxOptions{
		Image: "postgres:16-alpine",
		Env: map[string]string{
			"POSTGRES_PASSWORD": password,
			"POSTGRES_DB":       "bench",
		},
	}, 5432, "tls")
	if err := waitTCP(exposed.Host, exposed.HostPort, 90*time.Second); err != nil {
		return fail(res, "postgres tls port: %v", err)
	}
	out, err := execInSandbox(sb, fmt.Sprintf(`PGPASSWORD=%s psql -h 127.0.0.1 -U postgres -d bench -tAc "SELECT 1"`, password))
	if err != nil || strings.TrimSpace(out) != "1" {
		return fail(res, "psql in sandbox: %v out=%q", err, out)
	}
	res.PublicURL = exposed.PublicURL
	res.Success = true
	res.Notes = "postgres SELECT 1; TLS host port open"
	return res
}

func runRedisUpstash(ctx *RunContext) Result {
	res := baseResult(ctx, "redis-upstash", "SVC-04")
	if !ctx.Scenario.Has(harness.CapDocker) || !ctx.Scenario.Has(harness.CapDomain) {
		return skip(res, "requires docker + domain for TCP expose")
	}
	_, exposed := securedExpose(ctx.T, ctx.Client, ctx.Scenario, sdktypes.CreateSandboxOptions{
		Image: "redis:7-alpine",
	}, 6379, "tcp")
	if err := waitTCP(exposed.Host, exposed.HostPort, 90*time.Second); err != nil {
		return fail(res, "redis tcp: %v", err)
	}
	if err := redisRESPPing(exposed.Host, exposed.HostPort); err != nil {
		return fail(res, "redis RESP: %v", err)
	}
	res.PublicURL = fmt.Sprintf("tcp://%s:%d", exposed.Host, exposed.HostPort)
	res.Success = true
	res.Notes = "TCP RESP PING ok"
	return res
}

func runJupyterHeadless(ctx *RunContext) Result {
	res := baseResult(ctx, "jupyter-headless", "SVC-10")
	if !ctx.Scenario.Has(harness.CapDocker) || !ctx.Scenario.Has(harness.CapDomain) {
		return skip(res, "requires docker + domain")
	}
	const token = "itest-jupyter-token"
	_, exposed := securedExpose(ctx.T, ctx.Client, ctx.Scenario, sdktypes.CreateSandboxOptions{
		Image:            "jupyter/minimal-notebook:latest",
		ContainerCommand: []string{"start-notebook.sh", "--NotebookApp.token=" + token},
	}, 8888, "http")
	url := exposed.PublicURL
	if strings.Contains(url, "?") {
		url += "&token=" + token
	} else {
		url += "?token=" + token
	}
	if err := waitHTTP200(url, 2*time.Minute); err != nil {
		return fail(res, "jupyter url: %v", err)
	}
	res.PublicURL = url
	res.Success = true
	res.Notes = "tokenized JupyterLab 200"
	return res
}

func runGvisorKernelProbe(ctx *RunContext) Result {
	res := baseResult(ctx, "gvisor-kernel-probe", "ISO-01")
	if !ctx.Scenario.Has(harness.CapGvisor) {
		return skip(res, "scenario lacks gvisor capability")
	}
	if os.Getenv("AEROL_SIM_SKIP_GVISOR") == "1" {
		return skip(res, "gated: AEROL_SIM_SKIP_GVISOR=1 (runsc host-uds)")
	}
	dockerOut, err := kernelProbe(ctx, "")
	if err != nil {
		return fail(res, "docker probe: %v", err)
	}
	gvisorOut, err := kernelProbe(ctx, models.RuntimeGvisor)
	if err != nil {
		return fail(res, "gvisor probe: %v", err)
	}
	res.Success = dockerOut != "" && gvisorOut != ""
	res.Notes = fmt.Sprintf("docker=%q gvisor=%q", trim(dockerOut, 60), trim(gvisorOut, 60))
	return res
}

func kernelProbe(ctx *RunContext, runtime string) (string, error) {
	opts := sdktypes.CreateSandboxOptions{
		Image: harness.DefaultImage,
		Name:  harness.UniqueName(ctx.Scenario, ctx.T),
	}
	if runtime != "" {
		opts.Runtime = runtime
	}
	sb, err := ctx.Client.SDK().Create(context.Background(), opts)
	if err != nil {
		return "", err
	}
	ctx.T.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = ctx.Client.SDK().Destroy(cctx, sb.ID)
	})
	waitRunningTB(ctx.T, sb)
	ectx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	out, err := sb.ExecCommand(ectx, "cat /proc/sys/kernel/osrelease")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out.Stdout), nil
}

func runIsolateEgressExt(ctx *RunContext) Result {
	res := baseResult(ctx, "isolate-egress-ext", "EGR-08")
	if !ctx.Scenario.Has(harness.CapIsolate) {
		return skip(res, "scenario lacks isolate capability")
	}
	ref := uploadProbeBundle(ctx)
	allow := newIsolate(ctx, ref, "sim-egress", sdktypes.CreateSandboxOptions{NetworkAllowOut: []string{"example.com"}})
	block := newIsolate(ctx, ref, "sim-egress", sdktypes.CreateSandboxOptions{NetworkBlockAll: true})
	waitRunningTB(ctx.T, allow)
	waitRunningTB(ctx.T, block)
	allowOut := execFetch(ctx, allow, "/?t="+urlEncode("https://example.com/"))
	denyBlock := execFetch(ctx, block, "/?t="+urlEncode("https://example.com/"))
	if strings.Contains(allowOut, "status=403") {
		return fail(res, "allow sandbox denied: %q", allowOut)
	}
	if !strings.Contains(denyBlock, "status=403") {
		return fail(res, "block sandbox not denied: %q", denyBlock)
	}
	res.Success = true
	res.Runtime = "isolate"
	return res
}

func runClaudeCodeArch(ctx *RunContext) Result {
	res := baseResult(ctx, "claude-code-arch", "AI-01")
	key := strings.TrimSpace(os.Getenv("AEROL_SIM_ANTHROPIC_KEY"))
	if key == "" {
		key = strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY"))
	}
	if key == "" {
		return skip(res, "ANTHROPIC key absent — set AEROL_SIM_ANTHROPIC_KEY")
	}
	const maxTurns = 1
	deadline := time.Now().Add(2 * time.Minute)
	sb := ctx.Client.NewSandbox(ctx.T, sdktypes.CreateSandboxOptions{
		Image: harness.DefaultImage,
		Env:   map[string]string{"ANTHROPIC_API_KEY": key},
	})
	waitRunningTB(ctx.T, sb)
	for turn := 0; turn < maxTurns; turn++ {
		if time.Now().After(deadline) {
			return fail(res, "wall-timeout exceeded")
		}
		ectx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		out, err := sb.ExecCommand(ectx, `sh -c 'test -n "$ANTHROPIC_API_KEY" && echo arch-stub-ok'`)
		cancel()
		if err != nil {
			return fail(res, "agent stub exec: %v", err)
		}
		if !strings.Contains(out.Stdout, "arch-stub-ok") {
			return fail(res, "unexpected output: %q", out.Stdout)
		}
	}
	res.Success = true
	res.Notes = fmt.Sprintf("hard-capped stub turns=%d", maxTurns)
	return res
}

func baseResult(ctx *RunContext, simID, catID string) Result {
	for _, row := range harness.CatalogueRegistry {
		if row.ID == catID {
			return Result{
				SimID: simID, CatalogueID: catID, Question: row.Question,
				Category: row.Category, Subcategory: row.Subcategory, Runtime: "containerd",
			}
		}
	}
	return Result{SimID: simID, CatalogueID: catID, Question: simID}
}

func skip(res Result, format string, args ...any) Result {
	res.Skipped = true
	res.SkipReason = fmt.Sprintf(format, args...)
	return res
}

func fail(res Result, format string, args ...any) Result {
	res.Success = false
	res.Notes = fmt.Sprintf(format, args...)
	return res
}

func waitTCP(host string, port int, within time.Duration) error {
	deadline := time.Now().Add(within)
	var last error
	for time.Now().Before(deadline) {
		if err := tcpPing(host, port); err == nil {
			return nil
		} else {
			last = err
		}
		time.Sleep(3 * time.Second)
	}
	return last
}

func execInSandbox(sb *microvm.Sandbox, shell string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	out, err := sb.ExecCommand(ctx, "sh -c "+strconv.Quote(shell))
	if err != nil {
		return "", err
	}
	return out.Stdout, nil
}

func trim(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
