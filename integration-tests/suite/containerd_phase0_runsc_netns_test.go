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

// TestContainerdPhase0RunscNetnsProof boots runsc in a driver-provisioned netns
// (plans/containerd-engine.md Phase 0(c)).
// Record proof outcome in plans/containerd-engine-phase0-decisions.md (0c).
//
// Operator-run: requires runsc + containerd shim, native netns pool, and CNI.
// Example:
//
//	AEROL_CONTAINERD_RUNSC_SPIKE=1 \
//	SB_TOOLBOX_BINARY_PATH=/path/to/toolboxd \
//	SB_CONTAINERD_NATIVE_NETNS_POOL_ENABLED=true \
//	go test -tags=integration -run TestContainerdPhase0RunscNetnsProof ./integration-tests/suite/...
func TestContainerdPhase0RunscNetnsProof(t *testing.T) {
	if os.Getenv("AEROL_CONTAINERD_RUNSC_SPIKE") != "1" {
		t.Skip("set AEROL_CONTAINERD_RUNSC_SPIKE=1 to run live runsc netns proof")
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
		ContainerEngine:                  models.ContainerEngineContainerd,
		ContainerdSocket:                 socket,
		ToolboxBinaryPath:                toolbox,
		ToolboxMountPath:                 "/.aerol/toolboxd",
		ToolboxPort:                      2280,
		Runtime:                          models.RuntimeDocker,
		ContainerdNativeNetnsPoolEnabled: os.Getenv("SB_CONTAINERD_NATIVE_NETNS_POOL_ENABLED") == "true",
		DockerReadySocketEnabled:         true,
	})
	d := cntr.New(cfg, rules, slog.Default())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := d.Ping(ctx); err != nil {
		t.Fatalf("containerd ping: %v", err)
	}

	sandboxID := "phase0-runsc-" + time.Now().UTC().Format("150405")
	state, err := d.Create(ctx, models.CreateSandboxRequest{
		Image:            "alpine:3.20",
		Runtime:          models.RuntimeGvisor,
		ContainerCommand: []string{"sleep", "300"},
	}, sandboxID, "runsc-token", nil)
	if err != nil {
		t.Fatalf("runsc create: %v", err)
	}
	t.Cleanup(func() {
		_ = d.Destroy(context.Background(), &models.Sandbox{
			ID:          sandboxID,
			ContainerID: state.ContainerID,
			ContainerIP: state.ContainerIP,
		})
	})
	if state.ContainerIP == "" {
		t.Fatal("runsc sandbox has no container IP")
	}
	t.Logf("runsc netns proof ok sandbox_id=%s ip=%s container_id=%s",
		state.SandboxID, state.ContainerIP, state.ContainerID)
}
