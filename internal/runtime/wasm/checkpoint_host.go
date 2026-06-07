package wasm

import (
	"context"

	"github.com/aerol-ai/microvm/pkg/models"
)

// CheckpointHost is the Phase 6 drain/checkpoint/rehydrate surface the service
// layer type-asserts from runtime.Runtime.
type CheckpointHost interface {
	CheckpointSandbox(ctx context.Context, sandbox *models.Sandbox) (checkpointPath, cloneGen string, err error)
	RehydrateSandbox(ctx context.Context, sandbox *models.Sandbox) (*models.SandboxRuntimeState, error)
}

var _ CheckpointHost = (*Driver)(nil)
