package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	wasmruntime "github.com/aerol-ai/microvm/internal/runtime/wasm"
	"github.com/aerol-ai/microvm/pkg/models"
)

// DrainWasmSandboxes checkpoints passivatable/durable live WASM sandboxes during
// graceful shutdown (plans/wasm-runtime.md §4.3).
func (s *Service) DrainWasmSandboxes(ctx context.Context) error {
	if s.wasm == nil || !s.cfg.EnableWasm {
		return nil
	}
	host, ok := s.wasm.(wasmruntime.CheckpointHost)
	if !ok {
		return nil
	}

	known, err := s.store.List(ctx)
	if err != nil {
		return fmt.Errorf("drain wasm: list sandboxes: %w", err)
	}
	managed, err := s.wasm.ListManaged(ctx)
	if err != nil {
		return fmt.Errorf("drain wasm: list managed: %w", err)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, len(known))
	for _, sb := range known {
		if sb == nil || !s.isWasmSandbox(sb) {
			continue
		}
		if sb.Status != models.SandboxStatusStarted && sb.Status != models.SandboxStatusCreating {
			continue
		}
		if !wasmShouldCheckpoint(sb.Durability) {
			continue
		}
		if _, live := managed[sb.ID]; !live {
			continue
		}
		wg.Add(1)
		go func(sandbox *models.Sandbox) {
			defer wg.Done()
			if err := s.checkpointWasmSandbox(ctx, host, sandbox); err != nil {
				errCh <- err
			}
		}(sb)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

func wasmShouldCheckpoint(durability string) bool {
	switch durability {
	case models.DurabilityPassivatable, models.DurabilityDurable:
		return true
	default:
		return false
	}
}

func (s *Service) checkpointWasmSandbox(ctx context.Context, host wasmruntime.CheckpointHost, sandbox *models.Sandbox) error {
	path, gen, err := host.CheckpointSandbox(ctx, sandbox)
	if err != nil {
		s.logger.Error("wasm drain checkpoint failed",
			"sandbox_id", sandbox.ID,
			"durability", sandbox.Durability,
			"error", err,
		)
		_ = s.store.UpdateWasmCheckpoint(ctx, sandbox.ID,
			string(models.SandboxStatusPassivateFailed), "", sandbox.CloneGeneration, err.Error())
		if s.admitter != nil {
			s.admitter.Release(sandbox.ID)
		}
		return nil
	}
	if err := s.store.UpdateWasmCheckpoint(ctx, sandbox.ID,
		string(models.SandboxStatusPassivated), path, gen, ""); err != nil {
		return err
	}
	if s.admitter != nil {
		s.admitter.Release(sandbox.ID)
	}
	s.logger.Info("wasm sandbox passivated",
		"sandbox_id", sandbox.ID,
		"checkpoint", path,
		slog.String("clone_generation", gen),
	)
	if sandbox.Durability == models.DurabilityDurable && s.wasmCheckpointPusher != nil {
		go s.pushWasmCheckpointBestEffort(sandbox.ID, path)
	}
	return nil
}

func (s *Service) pushWasmCheckpointBestEffort(sandboxID, memSnapDir string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	result, err := s.wasmCheckpointPusher.PushOnce(ctx, sandboxID, memSnapDir)
	if err != nil {
		s.logger.Warn("wasm checkpoint AOCR push failed",
			"sandbox_id", sandboxID,
			"error", err,
		)
		return
	}
	if err := s.store.UpdateWasmRegistryPush(ctx, sandboxID, result.RegistryRef, result.Digest); err != nil {
		s.logger.Warn("wasm checkpoint AOCR push metadata persist failed",
			"sandbox_id", sandboxID,
			"error", err,
		)
	}
}

func (s *Service) rehydrateWasmIfNeeded(ctx context.Context, sandbox *models.Sandbox) (*models.Sandbox, error) {
	if sandbox == nil || !s.isWasmSandbox(sandbox) {
		return sandbox, nil
	}
	if sandbox.Status != models.SandboxStatusPassivated {
		return sandbox, nil
	}
	if !s.cfg.EnableWasm {
		return nil, fmt.Errorf("wasm runtime disabled; sandbox %s is passivated", sandbox.ID)
	}
	host, ok := s.wasm.(wasmruntime.CheckpointHost)
	if !ok {
		return nil, fmt.Errorf("wasm checkpoint host not available")
	}
	state, err := host.RehydrateSandbox(ctx, sandbox)
	if err != nil {
		if errors.Is(err, models.ErrSnapshotCorrupt) || errors.Is(err, models.ErrSnapshotFenced) {
			s.logger.Warn("wasm rehydrate failed; marking stopped",
				"sandbox_id", sandbox.ID,
				"error", err,
			)
			_ = s.store.UpdateStatus(ctx, sandbox.ID, models.SandboxStatusStopped, err.Error())
			return nil, err
		}
		return nil, err
	}
	sandbox.ContainerID = state.ContainerID
	sandbox.ContainerIP = state.ContainerIP
	sandbox.Status = state.Status
	sandbox.CheckpointPath = ""
	if err := s.store.Upsert(ctx, sandbox); err != nil {
		return nil, err
	}
	return s.store.Get(ctx, sandbox.ID)
}
