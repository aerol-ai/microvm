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
	s.startPeriodic(ctx, interval, s.cfg.WasmDrainTimeout, func(c context.Context) {
		_ = s.runWasmPeriodicCheckpoint(c)
	})
}

func (s *Service) runWasmPeriodicCheckpoint(ctx context.Context) error {
	host, ok := s.wasm.(wasmruntime.LiveCheckpointHost)
	if !ok {
		return nil
	}
	// Scan only WASM rows: this sweep checkpoints WASM sandboxes, so loading the
	// docker/firecracker rows just to filter them out wastes a full-fleet decode
	// every tick at scale.
	known, err := s.store.ListByRuntime(ctx, models.RuntimeWasm)
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
	s.startPeriodic(ctx, interval, 5*time.Minute, s.runWasmDurablePushSweep)
}

func (s *Service) runWasmDurablePushSweep(ctx context.Context) {
	// Orphan-ref retry: drop the tracking rows that cleanupWasmSandboxArtifacts
	// retained because their registry DeleteRef had not yet succeeded. This is
	// the retry vehicle that lets destroy decline to forget a ref it could not
	// clean up without leaving a permanent registry leak. Reuses this sweep's
	// ticker + pusher precondition rather than standing up a fourth janitor.
	s.runWasmOrphanRefSweep(ctx)

	known, err := s.store.ListByRuntime(ctx, models.RuntimeWasm)
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

// runWasmOrphanRefSweep retries DeleteRef for push-history rows whose sandbox
// is already gone, dropping each row once its manifest is confirmed absent
// (DeleteRef returns nil, which includes the already-deleted case). A row whose
// delete still fails is left for the next sweep, so a transient registry outage
// delays reclamation but never strands the row permanently — closing the
// no-vacuum gap left by destroy declining to block on the registry.
func (s *Service) runWasmOrphanRefSweep(ctx context.Context) {
	if s.wasmCheckpointPusher == nil || s.store == nil {
		return
	}
	orphans, err := s.store.ListOrphanedWasmCheckpointPushes(ctx, 0)
	if err != nil {
		s.logger.Warn("wasm orphan-ref sweep: list failed", "error", err)
		return
	}
	for _, p := range orphans {
		ref := strings.TrimSpace(p.RegistryRef)
		if ref != "" {
			if err := s.wasmCheckpointPusher.DeleteRef(ctx, ref); err != nil {
				s.logger.Warn("wasm orphan-ref sweep: delete failed; will retry",
					"push_id", p.ID, "sandbox_id", p.SandboxID, "registry_ref", ref, "error", err)
				continue
			}
		}
		if err := s.store.DeleteWasmCheckpointPush(ctx, p.ID); err != nil {
			s.logger.Warn("wasm orphan-ref sweep: row delete failed",
				"push_id", p.ID, "sandbox_id", p.SandboxID, "error", err)
		}
	}
}
