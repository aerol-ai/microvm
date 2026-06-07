package service

import (
	"context"

	"github.com/aerol-ai/microvm/pkg/models"
)

// reconcileWasmOfflineRow applies §4.5 durability policy when the WASM live
// set is empty or WASM is disabled. Returns true when the row was handled and
// reconcile should not destroy it.
func (s *Service) reconcileWasmOfflineRow(ctx context.Context, sandbox *models.Sandbox) bool {
	if sandbox == nil || !s.isWasmSandbox(sandbox) {
		return false
	}
	if !s.cfg.EnableWasm {
		switch sandbox.Status {
		case models.SandboxStatusPassivated, models.SandboxStatusAwaitingRuntime:
			return true
		case models.SandboxStatusStarted, models.SandboxStatusCreating, models.SandboxStatusStopped:
			if wasmShouldCheckpoint(sandbox.Durability) || sandbox.Durability == models.DurabilityDurable {
				if sandbox.Status != models.SandboxStatusAwaitingRuntime {
					_ = s.store.UpdateStatus(ctx, sandbox.ID, models.SandboxStatusAwaitingRuntime, "")
				}
				return true
			}
		}
		return false
	}
	switch sandbox.Status {
	case models.SandboxStatusPassivated, models.SandboxStatusAwaitingRuntime, models.SandboxStatusPassivateFailed:
		return true
	case models.SandboxStatusStarted, models.SandboxStatusCreating:
		if sandbox.Durability == models.DurabilityEphemeral {
			if s.admitter != nil {
				s.admitter.Release(sandbox.ID)
			}
			_ = s.store.UpdateStatus(ctx, sandbox.ID, models.SandboxStatusStopped, "ephemeral wasm lost on daemon restart")
			return true
		}
	}
	return false
}
