package service

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

func wasmCheckpointDir(cfgModulesDir, sandboxID string) string {
	return filepath.Join(strings.TrimSpace(cfgModulesDir), sandboxID, "mem.snap")
}

// ensureWasmCheckpointLocal pulls a durable checkpoint from AOCR when the local
// mem.snap directory is missing (failover / cross-node rehydrate).
func (s *Service) ensureWasmCheckpointLocal(ctx context.Context, sandbox *models.Sandbox) (checkpointPath string, err error) {
	if sandbox == nil {
		return "", fmt.Errorf("ensure wasm checkpoint: nil sandbox")
	}
	checkpointPath = strings.TrimSpace(sandbox.CheckpointPath)
	if checkpointPath == "" {
		checkpointPath = wasmCheckpointDir(s.cfg.WasmModulesDir, sandbox.ID)
	}
	if wasmengine.DirExists(checkpointPath) {
		return checkpointPath, nil
	}
	if sandbox.Durability != models.DurabilityDurable {
		return checkpointPath, fmt.Errorf("wasm checkpoint missing locally for %s", sandbox.ID)
	}
	if s.wasmCheckpointPusher == nil {
		return checkpointPath, fmt.Errorf("wasm checkpoint missing locally and AOCR pull is disabled")
	}
	registryRef := strings.TrimSpace(sandbox.WasmRegistryRef)
	if registryRef == "" {
		registryRef = s.wasmCheckpointPusher.DestRefFor(sandbox.ID)
	}
	if registryRef == "" {
		return checkpointPath, fmt.Errorf("wasm checkpoint missing locally and no AOCR ref for %s", sandbox.ID)
	}
	if err := s.wasmCheckpointPusher.PullOnce(ctx, registryRef, checkpointPath); err != nil {
		return checkpointPath, fmt.Errorf("pull wasm checkpoint %s: %w", registryRef, err)
	}
	if !wasmengine.DirExists(checkpointPath) {
		return checkpointPath, fmt.Errorf("wasm checkpoint pull succeeded but artifact missing at %s", checkpointPath)
	}
	if err := s.store.UpdateWasmCheckpoint(ctx, sandbox.ID,
		string(models.SandboxStatusPassivated), checkpointPath, sandbox.CloneGeneration, ""); err != nil {
		s.logger.Warn("wasm checkpoint pull metadata persist failed",
			"sandbox_id", sandbox.ID,
			"error", err,
		)
	}
	s.logger.Info("wasm checkpoint pulled from AOCR",
		"sandbox_id", sandbox.ID,
		"registry_ref", registryRef,
		"checkpoint_path", checkpointPath,
	)
	return checkpointPath, nil
}
