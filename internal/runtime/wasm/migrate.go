package wasm

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

// MigrateSandbox checkpoints a live sandbox (if needed) and copies mem.snap into
// destDir for cross-node handoff (plans/wasm-runtime.md §4.4).
func (d *Driver) MigrateSandbox(ctx context.Context, sandbox *models.Sandbox, destDir string) (string, string, error) {
	if sandbox == nil {
		return "", "", fmt.Errorf("migrate: nil sandbox")
	}
	destDir = strings.TrimSpace(destDir)
	if destDir == "" {
		return "", "", fmt.Errorf("migrate: dest dir required")
	}

	checkpointPath := strings.TrimSpace(sandbox.CheckpointPath)
	cloneGen := strings.TrimSpace(sandbox.CloneGeneration)

	d.mu.Lock()
	_, live := d.byID[sandbox.ID]
	d.mu.Unlock()
	if live {
		path, gen, err := d.CheckpointSandbox(ctx, sandbox)
		if err != nil {
			return "", "", fmt.Errorf("migrate checkpoint %s: %w", sandbox.ID, err)
		}
		checkpointPath = path
		cloneGen = gen
	}
	if checkpointPath == "" {
		checkpointPath = d.checkpointDir(sandbox.ID)
	}
	if !wasmengine.DirExists(checkpointPath) {
		return "", "", fmt.Errorf("migrate %s: checkpoint missing at %s", sandbox.ID, checkpointPath)
	}

	target := filepath.Join(destDir, sandbox.ID, "mem.snap")
	if err := copyDir(checkpointPath, target); err != nil {
		return "", "", fmt.Errorf("migrate copy %s -> %s: %w", checkpointPath, target, err)
	}
	return target, cloneGen, nil
}
