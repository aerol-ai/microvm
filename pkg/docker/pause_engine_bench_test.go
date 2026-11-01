//go:build linux && kerneltest

package docker

// What a restricted create costs on a real engine, in the privileged
// kernel-test container with the host's Docker socket mounted:
//
//	AEROL_TOOLBOXD=/abs/path/toolboxd go test -tags kerneltest -run '^$' \
//	    -bench DockerEngineCreate -benchtime 40x ./pkg/docker/
//
// dockerd bind-mounts toolboxd into every sandbox from the path it is
// given, so AEROL_TOOLBOXD must name the same file for this process and
// for dockerd. The host firewall here is this container's own netns: the
// rules are installed and timed, not enforced.

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"slices"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
)

const engineBenchImage = "alpine:3.20"

func engineClient(b *testing.B) *Client {
	b.Helper()
	if _, err := os.Stat("/var/run/docker.sock"); err != nil {
		b.Skip("needs the host's Docker socket at /var/run/docker.sock")
	}
	toolboxd := os.Getenv("AEROL_TOOLBOXD")
	if toolboxd == "" {
		b.Skip("set AEROL_TOOLBOXD to a linux toolboxd binary dockerd can see at the same path")
	}
	if out, err := exec.Command("iptables", "-w", "-P", "FORWARD", "ACCEPT").CombinedOutput(); err != nil {
		b.Fatalf("iptables: %v: %s", err, out)
	}
	rules, err := netrules.NewWithOptions(true, netrules.BackendNetlink, netrules.ChainDockerUser)
	if err != nil {
		b.Fatal(err)
	}
	if err := rules.EnsureChain(); err != nil {
		b.Fatal(err)
	}
	c, err := New(slog.New(slog.NewTextHandler(io.Discard, nil)), config.Config{
		ToolboxBinaryPath:          toolboxd,
		ToolboxMountPath:           "/usr/local/bin/toolboxd",
		ToolboxPort:                2280,
		DockerNetwork:              "bridge",
		Runtime:                    models.RuntimeDocker,
		HTTPClientTimeout:          time.Minute,
		DockerRuntimeWaitTimeout:   30 * time.Second,
		ToolboxWaitTimeout:         30 * time.Second,
		DockerReadinessPollInitial: 2 * time.Millisecond,
		DockerReadinessPollMax:     5 * time.Millisecond,
	}, rules)
	if err != nil {
		b.Fatal(err)
	}
	c.SetNetnsPauseImage("registry.k8s.io/pause:3.10")
	return c
}

func benchPct(v []time.Duration, p int) time.Duration {
	if len(v) == 0 {
		return 0
	}
	s := slices.Clone(v)
	slices.Sort(s)
	return s[(len(s)-1)*p/100]
}

// BenchmarkDockerEngineCreate creates and destroys sandboxes one at a time,
// with and without a rule, and reports each create's wall time, its engine
// part (pause, create, start, rules: the stages this change moves) and each
// destroy.
func BenchmarkDockerEngineCreate(b *testing.B) {
	c := engineClient(b)
	ctx := context.Background()
	if err := c.pullImageDedup(ctx, engineBenchImage, nil); err != nil {
		b.Fatal(err)
	}
	for _, mode := range []string{"open", "block-all"} {
		b.Run(mode, func(b *testing.B) {
			req := models.CreateSandboxRequest{Image: engineBenchImage, ContainerCommand: []string{"sleep", "3600"}, NetworkBlockAll: mode == "block-all"}
			var total, engine, pause, destroy []time.Duration
			for i := -1; i < b.N; i++ { // i == -1 warms up (a pull of the pause image)
				id := fmt.Sprintf("sb-bench-%s-%d-%d", mode, os.Getpid(), i+1)
				tctx, timing := WithCreateTiming(ctx)
				t0 := time.Now()
				st, err := c.Create(tctx, req, id, "tok", nil)
				took := time.Since(t0)
				if err != nil {
					b.Fatal(err)
				}
				var eng, ps time.Duration
				for _, s := range timing.Stages() {
					d := time.Duration(s.DurMS * float64(time.Millisecond))
					switch s.Name {
					case "docker_pause":
						ps = d
						eng += d
					case "docker_create", "docker_start", "docker_netrules":
						eng += d
					}
				}
				t1 := time.Now()
				if err := c.Destroy(ctx, &models.Sandbox{ID: id, ContainerID: st.ContainerID, ContainerIP: st.ContainerIP}); err != nil {
					b.Fatal(err)
				}
				if i >= 0 {
					total, engine, pause, destroy = append(total, took), append(engine, eng), append(pause, ps), append(destroy, time.Since(t1))
				}
			}
			b.ReportMetric(float64(benchPct(total, 50).Microseconds())/1000, "create_p50_ms")
			b.ReportMetric(float64(benchPct(total, 99).Microseconds())/1000, "create_p99_ms")
			b.ReportMetric(float64(benchPct(engine, 50).Microseconds())/1000, "engine_p50_ms")
			b.ReportMetric(float64(benchPct(engine, 99).Microseconds())/1000, "engine_p99_ms")
			b.ReportMetric(float64(benchPct(pause, 50).Microseconds())/1000, "pause_p50_ms")
			b.ReportMetric(float64(benchPct(destroy, 50).Microseconds())/1000, "destroy_p50_ms")
		})
	}
}
