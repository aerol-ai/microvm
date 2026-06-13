package service

import (
	"context"
	"strings"

	"github.com/aerol-ai/microvm/internal/store"
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
	// are gone there is no record left to GC them by, so the leak would be
	// permanent.
	//
	// No-vacuum rule: a push-history row is the only record that ties a sandbox
	// to its registry manifest, so a row is dropped ONLY after its ref is
	// confirmed gone (DeleteRef returns nil — which now includes already-absent
	// refs, see DeleteSnapshotRef). A ref whose delete transiently fails keeps
	// its row, and the orphan-ref sweep in runWasmDurablePushSweep retries it
	// after the sandbox row itself is gone. Destroy never blocks on the registry;
	// it just declines to forget what it could not yet clean up.
	if s.wasmCheckpointPusher != nil && s.store != nil {
		pushes, err := s.store.ListWasmCheckpointPushes(ctx, sandbox.ID)
		if err != nil {
			s.logger.Warn("wasm checkpoint push history list failed during cleanup",
				"sandbox_id", sandbox.ID,
				"error", err,
			)
		}
		// The :latest rolling tag and any WasmRegistryRef not yet tracked by a
		// push row have no tracking row to strand, so they are pure best-effort —
		// a failure here is retried only via the per-row refs below or a manual
		// cleanup, never leaving an untracked row behind.
		for _, ref := range s.untrackedWasmRefs(sandbox, pushes) {
			if err := s.wasmCheckpointPusher.DeleteRef(ctx, ref); err != nil {
				s.logger.Warn("delete wasm checkpoint AOCR ref failed",
					"sandbox_id", sandbox.ID, "registry_ref", ref, "error", err)
			}
		}
		// Per-row refs: drop the row only when its manifest is confirmed gone.
		for _, p := range pushes {
			ref := strings.TrimSpace(p.RegistryRef)
			if ref != "" {
				if err := s.wasmCheckpointPusher.DeleteRef(ctx, ref); err != nil {
					s.logger.Warn("delete wasm checkpoint AOCR ref failed; retaining tracking row for retry",
						"sandbox_id", sandbox.ID, "registry_ref", ref, "error", err)
					continue
				}
			}
			if err := s.store.DeleteWasmCheckpointPush(ctx, p.ID); err != nil {
				s.logger.Warn("delete wasm checkpoint push row failed",
					"sandbox_id", sandbox.ID, "push_id", p.ID, "error", err)
			}
		}
		if err := s.store.DeleteAllWasmStateKV(ctx, sandbox.ID); err != nil {
			return err
		}
		return nil
	}

	// No pusher (durable AOCR push disabled — the common single-node / local
	// case): there is no registry to leak into, so the tracking rows carry no
	// recoverable obligation. Bulk-delete them as before.
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

// untrackedWasmRefs returns the registry refs that have no push-history row to
// strand — the rolling :latest tag and a WasmRegistryRef that is not already
// covered by one of the supplied push rows. Deleting these is pure best-effort
// (no row is dropped on success), so a transient failure here cannot leave an
// orphaned tracking row.
func (s *Service) untrackedWasmRefs(sandbox *models.Sandbox, pushes []store.WasmCheckpointPushRecord) []string {
	tracked := make(map[string]struct{}, len(pushes))
	for _, p := range pushes {
		if ref := strings.TrimSpace(p.RegistryRef); ref != "" {
			tracked[ref] = struct{}{}
		}
	}
	var out []string
	if latest := strings.TrimSpace(s.wasmCheckpointPusher.DestRefTagged(sandbox.ID, "latest")); latest != "" {
		if _, ok := tracked[latest]; !ok {
			out = append(out, latest)
		}
	}
	if ref := strings.TrimSpace(sandbox.WasmRegistryRef); ref != "" {
		if _, ok := tracked[ref]; !ok {
			out = append(out, ref)
		}
	}
	return out
}
