package wasm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/aerol-ai/microvm/pkg/clonegen"
	"github.com/aerol-ai/microvm/pkg/models"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

func (d *Driver) checkpointDir(sandboxID string) string {
	return filepath.Join(d.cfg.ModulesDir, sandboxID, "mem.snap")
}

// CheckpointSandbox writes mem.snap for a live sandbox and tears down its worker.
func (d *Driver) CheckpointSandbox(ctx context.Context, sandbox *models.Sandbox) (string, string, error) {
	if sandbox == nil {
		return "", "", fmt.Errorf("checkpoint: nil sandbox")
	}
	inst, err := d.instance(sandbox.ID)
	if err != nil {
		return "", "", err
	}

	gen := clonegen.New("", d.logger)
	gen.Bump(time.Now().UnixNano())
	token, _ := gen.Current()

	outDir := d.checkpointDir(sandbox.ID)
	meta := wasmengine.SnapshotConfig{
		SchemaVersion:   1,
		Engine:          wasmengine.EngineNameWazero(),
		EngineVersion:   "wazero",
		WASIVersion:     "preview1",
		BaseModule:      wasmengine.SnapshotBaseModule{Digest: inst.moduleDigest, Size: moduleSize(inst.modulePath)},
		Entrypoint:      inst.entryExport,
		Durability:      durabilityOf(sandbox, inst),
		CloneGeneration: token,
	}

	client := d.newWorkerClient(inst.socketPath)
	_ = ctx
	if err := client.Checkpoint(sandbox.ID, outDir, meta); err != nil {
		workerKey := inst.workerKey
		if workerKey == "" {
			workerKey = sandbox.ID
		}
		_ = d.supervisor.Stop(workerKey)
		return "", "", fmt.Errorf("checkpoint sandbox %s: %w", sandbox.ID, err)
	}
	_ = client.StopInstance(sandbox.ID)
	workerKey := inst.workerKey
	if workerKey == "" {
		workerKey = sandbox.ID
	}
	_ = d.supervisor.Stop(workerKey)

	d.mu.Lock()
	delete(d.byID, sandbox.ID)
	d.mu.Unlock()

	return outDir, token, nil
}

func durabilityOf(sandbox *models.Sandbox, inst *sandboxInstance) string {
	if sandbox != nil && sandbox.Durability != "" {
		return sandbox.Durability
	}
	if inst != nil && inst.durability != "" {
		return inst.durability
	}
	return models.DurabilityPassivatable
}

func moduleSize(path string) int64 {
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return st.Size()
}
