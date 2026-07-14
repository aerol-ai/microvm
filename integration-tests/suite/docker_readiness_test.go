//go:build integration

package suite

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// UC-96 — on cluster deployments the docker create path should attribute
// readiness to the unix-socket push channel.
func TestDockerReadinessSocketPush(t *testing.T) {
	harness.Require(t, sc, "UC-96")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	sb, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
		Image: harness.DefaultImage,
		Name:  harness.UniqueName(sc, t),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() {
		_ = c.SDK().Destroy(context.Background(), sb.ID)
	})
	waitRunning(t, sb)

	source, ok := c.LastCreateReadinessSource()
	if !ok {
		t.Fatal("create response missing readiness Server-Timing source")
	}
	if source != "socket" {
		t.Fatalf("readiness source = %q, want socket (push path inactive?)", source)
	}
}

// UC-96b — non-root images must still complete the socket push (0666 + token).
func TestDockerReadinessSocketPushNonRoot(t *testing.T) {
	harness.Require(t, sc, "UC-96b")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	sb, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
		Image: "node:22-slim",
		Name:  harness.UniqueName(sc, t),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() {
		_ = c.SDK().Destroy(context.Background(), sb.ID)
	})
	waitRunning(t, sb)

	source, ok := c.LastCreateReadinessSource()
	if !ok || source != "socket" {
		t.Fatalf("readiness source = %q ok=%v, want socket", source, ok)
	}
}

// UC-96c — gVisor sandboxes must deliver readiness via the socket when runsc
// is configured with --host-uds=open.
func TestDockerReadinessSocketPushGvisor(t *testing.T) {
	harness.Require(t, sc, "UC-96c")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	sb, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
		Image:   harness.DefaultImage,
		Name:    harness.UniqueName(sc, t),
		Runtime: "gvisor",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() {
		_ = c.SDK().Destroy(context.Background(), sb.ID)
	})
	waitRunning(t, sb)

	source, ok := c.LastCreateReadinessSource()
	if !ok || source != "socket" {
		t.Fatalf("readiness source = %q ok=%v, want socket on gvisor", source, ok)
	}
}

// UC-96d — a socket-attributed create must mean the agent is genuinely
// serving, not merely that toolboxd dialed the socket. toolboxd announces only
// after its HTTP listener is bound (dial-after-listener contract), so an exec
// issued immediately after create returns must succeed without a readiness
// race. This guards against a false-ready regression where the push fires
// before the agent can answer.
func TestDockerReadinessSocketImpliesServingAgent(t *testing.T) {
	harness.Require(t, sc, "UC-96d")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	sb, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
		Image: harness.DefaultImage,
		Name:  harness.UniqueName(sc, t),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() {
		_ = c.SDK().Destroy(context.Background(), sb.ID)
	})

	source, ok := c.LastCreateReadinessSource()
	if !ok || source != "socket" {
		t.Fatalf("readiness source = %q ok=%v, want socket", source, ok)
	}

	// No waitRunning: the socket-ready signal must already imply a serving
	// agent. Exec straight away — a false-ready push would surface here as a
	// connection refused / 503 from the toolbox proxy.
	res, err := sb.Exec(ctx, sdktypes.ExecRequest{Command: "echo uc96d-ready"})
	if err != nil {
		t.Fatalf("exec right after socket-ready create: %v", err)
	}
	if !strings.Contains(res.Stdout, "uc96d-ready") {
		t.Fatalf("exec stdout = %q, want uc96d-ready", res.Stdout)
	}
}

// UC-97 is covered by pkg/docker unit tests (push disabled → health poll).
// The health-poll fallback only applies on a node with EnableCluster=false;
// push-based readiness ("socket") is correct whenever EnableCluster is true.
func TestDockerReadinessFallbackOnNonCluster(t *testing.T) {
	if sc.Satisfies(harness.UseCase{Requires: []harness.Capability{harness.CapCluster}}) {
		t.Skip("cluster scenario uses socket push; fallback covered elsewhere")
	}
	harness.Require(t, sc, "UC-11")
	c := client(t)
	// The scenario capability tags this as "non-cluster", but single-node
	// scenarios still run sandboxd as a 1-node cluster (seed → cluster-init sets
	// SB_ENABLE_CLUSTER=true), which turns push-based readiness ON — so "socket"
	// is correct there. DockerReadySocketEffective() gates on EnableCluster, not
	// on node count, so key the fallback assertion off the node's ACTUAL mode
	// (via /health) rather than the scenario tag. Only a truly non-cluster node
	// (local-mode, EnableCluster=false) exercises the health-poll fallback.
	if h, err := c.SDK().Health(context.Background()); err == nil && (h.ClusterTopology != "" || h.ClusterNodes > 0) {
		t.Skip("node runs EnableCluster=true (1-node cluster); push readiness is on, socket is correct")
	}
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Image: harness.DefaultImage,
		Name:  harness.UniqueName(sc, t),
	})
	waitRunning(t, sb)

	source, ok := c.LastCreateReadinessSource()
	if !ok {
		t.Fatal("missing Server-Timing readiness source")
	}
	if source != "health" {
		t.Fatalf("readiness source = %q, want health on non-cluster host", source)
	}
	if strings.Contains(source, "socket") {
		t.Fatal("socket push must be off outside cluster mode")
	}
}
