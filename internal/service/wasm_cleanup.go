package service

import (
	"context"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
)

// cleanupWasmSandboxArtifacts removes every durable side-effect a WASM sandbox
// leaves behind so a destroy/reconcile/event teardown does not leave a vacuum:
// the host-KV rows (§4.6), the AOCR checkpoint manifests (§4.8), and the local
// push-history rows that track them. Safe to call for non-WASM sandboxes (no-op)
// and idempotent under retry.
func (s *Service) cleanupWasmSandboxArtifacts(ctx context.Context, sandbox *models.Sandbox) error {
	if s == nil || sandbox == nil || !s.isWasmSandbox(sandbox) {
		return nil
	}

	// Delete AOCR checkpoint manifests BEFORE dropping the push-history rows.
	// Each durable push writes a per-digest tag (retained under keep-last-N) plus
	// a rolling :latest tag; sandbox.WasmRegistryRef only names the most recent
	// digest tag. Deleting just that ref would leak the older N-1 digest tags and
	// the :latest tag in the registry — and once the wasm_checkpoint_pushes rows
	// are gone there is no record left to GC them by, so the leak is permanent.
	// Enumerate every tracked ref (+ :latest) and delete each first. Registry
	// deletes are best-effort with loud logging, mirroring the caddy/image
	// cleanup discipline elsewhere in the destroy path: a registry hiccup must
	// not block the sandbox row from being removed.
	//
	// Residual tradeoff (phase 1): if a DeleteRef transiently fails we still drop
	// the push-history rows below, so that specific manifest becomes an
	// unrecoverable registry leak. Accepted because destroy cannot block on the
	// registry; a future hardening is to hand failed refs to a janitor (like
	// pending_image_gc) instead of dropping their tracking rows.
	if s.wasmCheckpointPusher != nil {
		refs := make(map[string]struct{})
		if s.store != nil {
			pushes, err := s.store.ListWasmCheckpointPushes(ctx, sandbox.ID)
			if err != nil {
				s.logger.Warn("wasm checkpoint push history list failed during cleanup",
					"sandbox_id", sandbox.ID,
					"error", err,
				)
			} else {
				for _, p := range pushes {
					if ref := strings.TrimSpace(p.RegistryRef); ref != "" {
						refs[ref] = struct{}{}
					}
				}
			}
		}
		if ref := strings.TrimSpace(sandbox.WasmRegistryRef); ref != "" {
			refs[ref] = struct{}{}
		}
		if latest := strings.TrimSpace(s.wasmCheckpointPusher.DestRefTagged(sandbox.ID, "latest")); latest != "" {
			refs[latest] = struct{}{}
		}
		for ref := range refs {
			if err := s.wasmCheckpointPusher.DeleteRef(ctx, ref); err != nil {
				s.logger.Warn("delete wasm checkpoint AOCR ref failed",
					"sandbox_id", sandbox.ID,
					"registry_ref", ref,
					"error", err,
				)
			}
		}
	}

	if s.store != nil {
		if err := s.store.DeleteAllWasmStateKV(ctx, sandbox.ID); err != nil {
			return err
		}
		if err := s.store.DeleteAllWasmCheckpointPushes(ctx, sandbox.ID); err != nil {
			return err
		}
	}
	return nil
}
