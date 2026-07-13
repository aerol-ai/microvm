//go:build integration && linux

package suite

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	cntr "github.com/aerol-ai/microvm/internal/runtime/containerd"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestContainerdPhase0CreateSpike runs a CreateSandbox-equivalent cold create
// against live containerd (plans/containerd-engine.md Phase 0(b)).
// Record measured elapsed in plans/containerd-engine-phase0-decisions.md (0b).
//
// Operator-run only — skipped unless AEROL_CONTAINERD_SPIKE=1 and the socket
// exists. Example:
//
//	AEROL_CONTAINERD_SPIKE=1 \
//	SB_TOOLBOX_BINARY_PATH=/path/to/toolboxd \
//	go test -tags=integration -run TestContainerdPhase0CreateSpike ./integration-tests/suite/...
func TestContainerdPhase0CreateSpike(t *testing.T) {
	if os.Getenv("AEROL_CONTAINERD_SPIKE") != "1" {
		t.Skip("set AEROL_CONTAINERD_SPIKE=1 to run live containerd spike")
	}
	toolbox := strings.TrimSpace(os.Getenv("SB_TOOLBOX_BINARY_PATH"))
	if toolbox == "" {
		t.Fatal("SB_TOOLBOX_BINARY_PATH is required")
	}
	socket := strings.TrimSpace(os.Getenv("SB_CONTAINERD_SOCKET"))
	if socket == "" {
		socket = "/run/containerd/containerd.sock"
	}
	if _, err := os.Stat(socket); err != nil {
		t.Skipf("containerd socket %s not present: %v", socket, err)
	}

	rules, err := netrules.New(false)
	if err != nil {
		t.Fatal(err)
	}
	cfg := cntr.FromDaemonConfig(config.Config{
		ContainerEngine:   models.ContainerEngineContainerd,
		ContainerdSocket:  socket,
		ToolboxBinaryPath: toolbox,
		ToolboxMountPath:  "/.aerol/toolboxd",
		ToolboxPort:       2280,
		Runtime:           models.RuntimeDocker,
	})
	d := cntr.New(cfg, rules, slog.Default())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := d.Ping(ctx); err != nil {
		t.Fatalf("containerd ping: %v", err)
	}

	sandboxID := "phase0-spike-" + time.Now().UTC().Format("150405")
	start := time.Now()
	state, err := d.Create(ctx, models.CreateSandboxRequest{
		Image:            "alpine:3.20",
		ContainerCommand: []string{"sleep", "300"},
	}, sandboxID, "phase0-token", nil)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() {
		_ = d.Destroy(context.Background(), &models.Sandbox{
			ID:          sandboxID,
			ContainerID: state.ContainerID,
			ContainerIP: state.ContainerIP,
		})
	})

	t.Logf("containerd phase0 cold create elapsed=%s sandbox_id=%s container_id=%s ip=%s",
		elapsed, state.SandboxID, state.ContainerID, state.ContainerIP)

	const phase0ColdBudget = 15 * time.Second // generous operator gate; §8 targets 130ms p50 on bench topology
	if elapsed > phase0ColdBudget {
		t.Fatalf("cold create took %s, over %s operator budget", elapsed, phase0ColdBudget)
	}
}
