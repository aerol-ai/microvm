package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

// recreateWasmDurableSandbox restores a durable WASM sandbox on a new owner
// after cluster failover: pull mem.snap from AOCR when needed, rehydrate, replay ports.
func (s *Service) recreateWasmDurableSandbox(ctx context.Context, id string, spec models.CreateSandboxRequest, exposedPorts map[int]cluster.ExposedPortRoute) error {
	existing, err := s.store.Get(ctx, id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if existing != nil {
		if _, err := s.ensureWasmCheckpointLocal(ctx, existing); err != nil {
			return fmt.Errorf("recreate %s: %w", id, err)
		}
		if _, err := s.rehydrateWasmIfNeeded(ctx, existing, nil); err != nil {
			return fmt.Errorf("recreate %s: rehydrate: %w", id, err)
		}
		s.ReconstructWakeArmedIfNeeded(ctx, existing)
		return s.replayClusterExposedPorts(ctx, id, exposedPorts)
	}

	moduleRef := models.ModuleRefForCreate(spec)
	if moduleRef == "" {
		return fmt.Errorf("recreate %s: module_ref required for wasm", id)
	}
	checkpointPath := wasmCheckpointDir(s.cfg.WasmModulesDir, id)
	seed := &models.Sandbox{
		ID:                 id,
		Runtime:            models.RuntimeWasm,
		Durability:         models.DurabilityDurable,
		ModuleRef:          moduleRef,
		Image:              strings.TrimSpace(spec.Image),
		Status:             models.SandboxStatusPassivated,
		AllowPublicTraffic: spec.AllowPublicTraffic,
	}
	if _, err := s.ensureWasmCheckpointLocal(ctx, seed); err != nil {
		return fmt.Errorf("recreate %s: pull checkpoint: %w", id, err)
	}
	if snap, readErr := wasmengine.ReadSnapshotDir(checkpointPath, wasmengine.EngineNameWazero()); readErr == nil {
		seed.CloneGeneration = snap.Config.CloneGeneration
		if seed.ModuleDigest == "" {
			seed.ModuleDigest = snap.Config.BaseModule.Digest
		}
	}
	seed.CheckpointPath = checkpointPath
	now := time.Now().UTC()
	seed.CPU = spec.CPU
	seed.MemoryMB = spec.MemoryMB
	seed.DiskGB = spec.DiskGB
	seed.Env = spec.Env
	seed.NetworkBlockAll = spec.NetworkBlockAll
	seed.NetworkAllowOut = spec.NetworkAllowOut
	seed.NetworkDenyOut = spec.NetworkDenyOut
	seed.ContainerCommand = spec.ContainerCommand
	seed.CreatedAt = now
	seed.UpdatedAt = now
	seed.OwnerRef = ownerRefForCreate(ctx)
	if err := s.store.Upsert(ctx, seed); err != nil {
		return fmt.Errorf("recreate %s: persist row: %w", id, err)
	}
	if _, err := s.rehydrateWasmIfNeeded(ctx, seed, nil); err != nil {
		return fmt.Errorf("recreate %s: rehydrate: %w", id, err)
	}
	return s.replayClusterExposedPorts(ctx, id, exposedPorts)
}
