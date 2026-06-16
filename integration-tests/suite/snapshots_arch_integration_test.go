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
