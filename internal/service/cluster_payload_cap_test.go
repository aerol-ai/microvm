package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

// oversizedClusterSpec builds a request whose non-secret recovery record
// encodes well past the raft inline cap.
func oversizedClusterSpec() models.CreateSandboxRequest {
	return models.CreateSandboxRequest{
		Image: "registry.example/" + strings.Repeat("x", 5000),
	}
}

// TestCreateSandboxRejectsOversizedClusterPayload pins the create-time half
// of the size cap (plans/remove-legacy-recovery-blob-path.md §3): in cluster
// mode a spec whose recovery record cannot ride a raft entry fails validation
// BEFORE any admission or container work — a clean 400, not a placement
// failure after the sandbox half-exists.
func TestCreateSandboxRejectsOversizedClusterPayload(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, rt)
	svc.cfg.EnableCluster = true
	svc.cfg.NodeRole = config.NodeRoleWorker

	_, err := svc.CreateSandbox(ctx, oversizedClusterSpec())
	if !errors.Is(err, cluster.ErrRecoveryPayloadTooLarge) {
		t.Fatalf("CreateSandbox() error = %v, want ErrRecoveryPayloadTooLarge", err)
	}
	if rt.createCalls != 0 {
		t.Fatalf("runtime Create calls = %d, want 0 (reject before container work)", rt.createCalls)
	}
}

// TestCreateSandboxOversizedSpecAllowedSingleNode is the control: the cap is
// a raft wire-format constraint, so single-node deployments (no raft, no
// replication) must not inherit it.
func TestCreateSandboxOversizedSpecAllowedSingleNode(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, rt)

	if _, err := svc.CreateSandbox(ctx, oversizedClusterSpec()); err != nil {
		t.Fatalf("CreateSandbox() single-node error = %v, want success", err)
	}
	if rt.createCalls != 1 {
		t.Fatalf("runtime Create calls = %d, want 1", rt.createCalls)
	}
}
