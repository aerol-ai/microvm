package wasm

import (
	"context"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// CheckpointHost is the Phase 6 drain/checkpoint/rehydrate surface the service
// layer type-asserts from runtime.Runtime.
type CheckpointHost interface {
	CheckpointSandbox(ctx context.Context, sandbox *models.Sandbox) (checkpointPath, cloneGen string, err error)
	RehydrateSandbox(ctx context.Context, sandbox *models.Sandbox, hostMounts []mounts.ContainerBind) (*models.SandboxRuntimeState, error)
}

// MigrationHost streams a boundary checkpoint to a sibling node (§4.4).
type MigrationHost interface {
	MigrateSandbox(ctx context.Context, sandbox *models.Sandbox, destDir string) (checkpointPath, cloneGen string, err error)
}

// StartHost reconstructs a stopped sandbox using persisted sandbox metadata.
type StartHost interface {
	StartSandbox(ctx context.Context, sandbox *models.Sandbox, hostMounts []mounts.ContainerBind) (*models.SandboxRuntimeState, error)
}

var _ CheckpointHost = (*Driver)(nil)

var _ MigrationHost = (*Driver)(nil)

var _ StartHost = (*Driver)(nil)

var _ GuestListenPortSyncer = (*Driver)(nil)
