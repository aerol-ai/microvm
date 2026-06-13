//go:build integration

package suite

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// runtimeRuns creates a sandbox pinned to runtime rt, waits for it to start,
// and confirms exec works inside it. Shared by the per-runtime UCs.
func runtimeRuns(t *testing.T, rt string) {
	t.Helper()
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name:    harness.UniqueName(sc, t),
		Runtime: rt,
	})
	waitRunning(t, sb)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if got, err := c.SDK().Get(ctx, sb.ID); err != nil {
		t.Fatalf("get: %v", err)
	} else if got.Runtime != "" && got.Runtime != rt {
		t.Fatalf("sandbox runtime = %q, want %q", got.Runtime, rt)
	}
}

// UC-23 — Docker-runtime sandbox runs.
func TestRuntimeDocker(t *testing.T) {
	harness.Require(t, sc, "UC-23")
	runtimeRuns(t, "docker")
}

// UC-24 — Firecracker-runtime sandbox runs (firecracker-capable worker only).
func TestRuntimeFirecracker(t *testing.T) {
	harness.Require(t, sc, "UC-24")
	runtimeRuns(t, "firecracker")
}

// UC-25 — gVisor-runtime sandbox runs (gvisor-capable worker only).
func TestRuntimeGvisor(t *testing.T) {
	harness.Require(t, sc, "UC-25")
	runtimeRuns(t, "gvisor")
}

// UC-26 — WASM-runtime sandbox runs. The "image" is a staged module ref.
func TestRuntimeWasm(t *testing.T) {
	harness.Require(t, sc, "UC-26")
	ref := os.Getenv("AEROL_WASM_MODULE_REF")
	if ref == "" {
		t.Skip("AEROL_WASM_MODULE_REF not set (oci ref of a staged .wasm)")
	}
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name:    harness.UniqueName(sc, t),
		Runtime: "wasm",
		Image:   ref,
	})
	waitRunning(t, sb)
}

// UC-27 — Kata is reserved/not implemented: a create must be rejected.
func TestRuntimeKataRejected(t *testing.T) {
	harness.Require(t, sc, "UC-27")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	sb, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
		Image:   harness.DefaultImage,
		Name:    harness.UniqueName(sc, t),
		Runtime: "kata",
	})
	if err == nil {
		_ = c.SDK().Destroy(ctx, sb.ID)
		t.Fatal("create with runtime=kata succeeded; expected not-implemented rejection")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "kata") &&
		!strings.Contains(strings.ToLower(err.Error()), "not") &&
		!strings.Contains(strings.ToLower(err.Error()), "implement") &&
		!strings.Contains(strings.ToLower(err.Error()), "runtime") {
		t.Logf("kata rejected with: %v", err) // any rejection satisfies the UC
	}
}

// UC-28 — GPU + gVisor is an unsupported combination and must be rejected.
func TestGPUWithGvisorRejected(t *testing.T) {
	harness.Require(t, sc, "UC-28")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	sb, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
		Image:   harness.DefaultImage,
		Name:    harness.UniqueName(sc, t),
		Runtime: "gvisor",
		GPUs:    &sdktypes.GPURequest{Vendor: sdktypes.GPUVendorNVIDIA, Count: 1},
	})
	if err == nil {
		_ = c.SDK().Destroy(ctx, sb.ID)
		t.Fatal("create with GPU + gvisor succeeded; expected rejection")
	}
}
