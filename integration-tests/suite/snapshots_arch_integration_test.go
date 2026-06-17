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

// UC-78 — offline arch guard: a create from an AOCR cluster-snapshot ref whose
// --arch-<goarch> tag doesn't match the host is rejected up front in
// NormalizeCreateImageDistribution, before any placement, pull, or runtime
// dispatch. Runs on every scenario (Requires: nil) — it needs neither
// firecracker nor a cluster, just the AOCR ref classifier (the provider
// defaults its host to aocr.aerol.ai even when the mirror is disabled).
//
// We tag the ref with an architecture that matches no host (riscv64) so the
// guard fires deterministically whether the runner is amd64 or arm64; UC-79
// covers the realistic amd64-snapshot-on-arm64-host live case.
func TestUC78_ForeignArchSnapshotRefRejectedOffline(t *testing.T) {
	harness.Require(t, sc, "UC-78")

	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	foreignRef := "aocr.aerol.ai/cluster/itest/snapshots/uc78-foreign:latest--arch-riscv64"
	sb, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
		Image: foreignRef,
		Name:  harness.UniqueName(sc, t),
	})
	if err == nil {
		_ = c.SDK().Destroy(ctx, sb.ID)
		t.Fatal("expected create from foreign-arch snapshot ref to be rejected offline")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "arch") {
		t.Fatalf("error should mention architecture mismatch, got: %v", err)
	}
}

// UC-79 — live homogeneity enforcement: an arm64 cluster refuses an x86-tagged
// AOCR snapshot ref instead of loading garbage into the VMM.
func TestUC79_ForeignArchSnapshotRejectedOnARM64Cluster(t *testing.T) {
	harness.Require(t, sc, "UC-79")

	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	foreignRef := "aocr.aerol.ai/cluster/itest/snapshots/uc79-foreign:latest--arch-amd64"
	_, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{
		Runtime: "firecracker",
		Image:   foreignRef,
		Name:    harness.UniqueName(sc, t),
	})
	if err == nil {
		t.Fatal("expected create from foreign-arch snapshot ref to fail")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "arch") {
		t.Fatalf("error should mention architecture mismatch, got: %v", err)
	}
}
