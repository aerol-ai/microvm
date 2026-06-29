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

// UC-97 is covered by pkg/docker unit tests (push disabled → health poll).
// Non-cluster scenarios (local-mode, single-node) exercise the fallback on
// live infra because EnableCluster=false keeps the push path off.
func TestDockerReadinessFallbackOnNonCluster(t *testing.T) {
	if sc.Satisfies(harness.UseCase{Requires: []harness.Capability{harness.CapCluster}}) {
		t.Skip("cluster scenario uses socket push; fallback covered elsewhere")
	}
	harness.Require(t, sc, "UC-11")
	c := client(t)
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
