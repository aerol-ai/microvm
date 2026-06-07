package service

import (
	"context"
	"strings"
	"time"

	wasmruntime "github.com/aerol-ai/microvm/internal/runtime/wasm"
	"github.com/aerol-ai/microvm/pkg/models"
)

// StartWasmPeriodicCheckpoint launches optional boundary checkpoint sweeps.
func (s *Service) StartWasmPeriodicCheckpoint(ctx context.Context) {
	if s == nil || !s.cfg.EnableWasm || s.wasm == nil {
		return
	}
	interval := s.cfg.WasmCheckpointInterval
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sweepCtx, cancel := context.WithTimeout(ctx, s.cfg.WasmDrainTimeout)
				_ = s.runWasmPeriodicCheckpoint(sweepCtx)
				cancel()
			}
		}
	}()
}

func (s *Service) runWasmPeriodicCheckpoint(ctx context.Context) error {
	host, ok := s.wasm.(wasmruntime.LiveCheckpointHost)
	if !ok {
		return nil
	}
	known, err := s.store.List(ctx)
	if err != nil {
		return err
	}
	managed, err := s.wasm.ListManaged(ctx)
	if err != nil {
		return err
	}
	eligible := make([]*models.Sandbox, 0, len(known))
	for _, sb := range known {
		if sb == nil || !s.isWasmSandbox(sb) {
			continue
		}
		if sb.Status != models.SandboxStatusStarted {
			continue
		}
		if !wasmShouldCheckpoint(sb.Durability) {
			continue
		}
		if _, live := managed[sb.ID]; !live {
			continue
		}
		eligible = append(eligible, sb)
	}
	return s.runWasmCheckpointPool(ctx, eligible, func(sandbox *models.Sandbox) error {
		return s.checkpointLiveWasmSandbox(ctx, host, sandbox)
	})
}

// StartWasmDurablePushSweep retries AOCR push for durable checkpoints missing registry metadata.
func (s *Service) StartWasmDurablePushSweep(ctx context.Context) {
	if s == nil || s.wasmCheckpointPusher == nil {
		return
	}
	interval := s.cfg.WasmDurablePushInterval
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sweepCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
				s.runWasmDurablePushSweep(sweepCtx)
				cancel()
			}
		}
	}()
}

func (s *Service) runWasmDurablePushSweep(ctx context.Context) {
	known, err := s.store.List(ctx)
	if err != nil {
		s.logger.Warn("wasm durable push sweep: list failed", "error", err)
		return
	}
	for _, sb := range known {
		if sb == nil || !s.isWasmSandbox(sb) || sb.Durability != models.DurabilityDurable {
			continue
		}
		path := strings.TrimSpace(sb.CheckpointPath)
		if path == "" {
			path = wasmCheckpointDir(s.cfg.WasmModulesDir, sb.ID)
		}
		if path == "" {
			continue
		}
		if strings.TrimSpace(sb.WasmRegistryRef) != "" {
			continue
		}
		if sb.Status != models.SandboxStatusPassivated && sb.Status != models.SandboxStatusPassivateFailed {
			continue
		}
		s.pushWasmCheckpointBestEffort(sb.ID, path)
		_ = ctx
	}
}
